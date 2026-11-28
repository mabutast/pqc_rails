# frozen_string_literal: true

require "active_record"

RSpec.describe PqcRails::Session::Encryptor do
  let(:keypair) { PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair } }
  let(:encryptor) { described_class.new(keypair, pq_alg_name: :ml_kem_512) }

  describe "#encrypt / #decrypt" do
    it "セッションハッシュをラウンドトリップできる" do
      session = { "user_id" => 42, "_csrf_token" => "abc123" }

      blob = encryptor.encrypt(session)

      expect(encryptor.decrypt(blob)).to eq(session)
    end

    it "暗号化結果はBase64文字列を返す(Cookie値として安全に扱える)" do
      blob = encryptor.encrypt({ "user_id" => 1 })

      expect(blob).to be_a(String)
      expect { Base64.strict_decode64(blob) }.not_to raise_error
    end

    it "空のセッションハッシュも扱える" do
      blob = encryptor.encrypt({})

      expect(encryptor.decrypt(blob)).to eq({})
    end

    it "暗号化するたびに異なるBase64文字列になる(KEMが毎回再ランダム化されるため)" do
      session = { "user_id" => 42 }

      blob_a = encryptor.encrypt(session)
      blob_b = encryptor.encrypt(session)

      expect(blob_a).not_to eq(blob_b)
    end

    it "異なる鍵ペアのEncryptorでは復号できない" do
      other_keypair = PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair }
      other_encryptor = described_class.new(other_keypair, pq_alg_name: :ml_kem_512)

      blob = encryptor.encrypt({ "user_id" => 42 })

      expect { other_encryptor.decrypt(blob) }.to raise_error(PqcRails::Error)
    end
  end

  describe "暗号文のメタデータ(形式バージョン・アルゴリズムID・鍵ID)" do
    around do |example|
      original_format = PqcRails.configuration.ciphertext_format
      original_until = PqcRails.configuration.accept_legacy_cookies_until
      example.run
    ensure
      PqcRails.configuration.ciphertext_format = original_format
      PqcRails.configuration.accept_legacy_cookies_until = original_until
    end

    let(:legacy_keypair) { PqcRails::HybridKem::Keypair.new(keypair.public_key, keypair.secret_key) }
    let(:legacy_encryptor) { described_class.new(legacy_keypair, pq_alg_name: :ml_kem_512) }

    def decoded(blob) = Base64.strict_decode64(blob)

    # 公開鍵だけで旧形式(v0)のCookieを作る。
    def forge_legacy(public_key, session)
      PqcRails::HybridKem.open(:ml_kem_512) do |hybrid|
        encap = hybrid.encapsulate(public_key)
        body = PqcRails::EnvelopeCipher.new(encap.shared_secret).encrypt(Marshal.dump(session))
        Base64.strict_encode64(PqcRails::BlobPacking.pack(encap.ciphertext, body))
      end
    end

    # 公開鍵だけを使い、KEMの共有鍵をそのままAES鍵にしてv1形式のCookieを作る。
    # 秘密鍵を持たない者が作れるCookieに当たる。
    def forge_with_public_key(public_key, session)
      algorithm_id = PqcRails::CiphertextFormat.algorithm_id(:ml_kem_512)
      key_id = PqcRails::CiphertextFormat.key_id(public_key)
      associated_data = PqcRails::CiphertextFormat.associated_data(algorithm_id: algorithm_id, key_id: key_id,
                                                                  purpose: :session)
      header = [PqcRails::CiphertextFormat::VERSION, algorithm_id.bytesize].pack("CC") + algorithm_id + [key_id].pack("H4")

      PqcRails::HybridKem.open(:ml_kem_512) do |hybrid|
        encap = hybrid.encapsulate(public_key)
        encrypted = PqcRails::EnvelopeCipher.new(encap.shared_secret)
                                            .encrypt(Marshal.dump(session), associated_data: associated_data)
        Base64.strict_encode64(header + PqcRails::BlobPacking.pack(encap.ciphertext, encrypted))
      end
    end

    it "公開鍵だけで作ったCookieは復号できない(作成元の認証)" do
      forged = forge_with_public_key(keypair.public_key, { "user_id" => 1 })

      expect { encryptor.decrypt(forged) }.to raise_error(PqcRails::Error)
    end

    it "先頭に[形式バージョン][アルゴリズムIDの長さ][アルゴリズムID][鍵ID 2バイト]を持つ" do
      bytes = decoded(encryptor.encrypt({ "user_id" => 1 }))
      algorithm_id = "X25519+ML-KEM-512"

      expect(bytes.getbyte(0)).to eq(1)
      expect(bytes.getbyte(1)).to eq(algorithm_id.bytesize)
      expect(bytes[2, algorithm_id.bytesize]).to eq(algorithm_id)
      expect(bytes[2 + algorithm_id.bytesize, 2].unpack1("H4"))
        .to eq(PqcRails::CiphertextFormat.key_id(keypair.public_key))
    end

    it "暗号文に書かれたアルゴリズムで復号する(設定のアルゴリズムを変えても既存のCookieを読める)" do
      keypair_1024 = PqcRails::HybridKem.open(:ml_kem_1024) { |hybrid| hybrid.generate_keypair }
      blob = described_class.new(keypair_1024, pq_alg_name: :ml_kem_1024).encrypt({ "user_id" => 7 })

      expect(described_class.new(keypair_1024, pq_alg_name: :ml_kem_512).decrypt(blob)).to eq({ "user_id" => 7 })
    end

    it "アルゴリズムIDを書き換えると復号できない" do
      bytes = decoded(encryptor.encrypt({ "user_id" => 1 }))
      bytes[2, "X25519+ML-KEM-512".bytesize] = "X25519+ML-KEM-768"

      expect { encryptor.decrypt(Base64.strict_encode64(bytes)) }.to raise_error(PqcRails::Error)
    end

    it "鍵IDが一致しない鍵では、KEMの復号を行わずにPqcRails::Errorを送出する" do
      other_keypair = PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair }
      blob = encryptor.encrypt({ "user_id" => 1 })
      allow(PqcRails::HybridKem).to receive(:open).and_call_original

      expect do
        described_class.new(other_keypair, pq_alg_name: :ml_kem_512).decrypt(blob)
      end.to raise_error(PqcRails::Error, /key id/)
      expect(PqcRails::HybridKem).not_to have_received(:open)
    end

    it "途中で切れたCookie(見出しだけ・本体の途中まで)はPqcRails::Errorを送出する" do
      bytes = decoded(encryptor.encrypt({ "user_id" => 1 }))
      header_length = 4 + bytes.getbyte(1)

      [bytes[0, 1], bytes[0, 3], bytes[0, header_length], bytes[0, header_length + 3],
       bytes[0, header_length + 40], bytes[0..-2]].each do |bad|
        expect { encryptor.decrypt(Base64.strict_encode64(bad)) }.to raise_error(PqcRails::Error)
      end
    end

    it "途中で切れた旧形式(v0)のCookieもPqcRails::Errorを送出する" do
      PqcRails.configuration.accept_legacy_cookies_until = Time.now + 60
      PqcRails.configuration.ciphertext_format = :v0
      bytes = decoded(legacy_encryptor.encrypt({ "user_id" => 1 }))
      PqcRails.configuration.ciphertext_format = :v1

      [bytes[0, 2], bytes[0, 4], bytes[0, 40], bytes[0..-2]].each do |bad|
        expect { legacy_encryptor.decrypt(Base64.strict_encode64(bad)) }.to raise_error(PqcRails::Error)
      end
    end

    it "末尾に余分なバイトがあるCookie(新形式・旧形式)はPqcRails::Errorを送出する" do
      PqcRails.configuration.accept_legacy_cookies_until = Time.now + 60
      PqcRails.configuration.ciphertext_format = :v0
      legacy = decoded(legacy_encryptor.encrypt({ "user_id" => 1 }))
      PqcRails.configuration.ciphertext_format = :v1
      current = decoded(encryptor.encrypt({ "user_id" => 1 }))

      { legacy_encryptor => legacy, encryptor => current }.each do |reader, bytes|
        expect { reader.decrypt(Base64.strict_encode64(bytes + "\x00".b)) }
          .to raise_error(PqcRails::Error, /trailing/)
      end
    end

    it "未知の形式バージョンはPqcRails::Errorを送出する" do
      bytes = decoded(encryptor.encrypt({ "user_id" => 1 }))
      bytes.setbyte(0, 3)

      expect { encryptor.decrypt(Base64.strict_encode64(bytes)) }.to raise_error(PqcRails::Error, /version/)
    end

    context "ciphertext_format = :v0 のとき" do
      before { PqcRails.configuration.ciphertext_format = :v0 }

      it "0.3.0の鍵では旧形式([4バイト長][KEM暗号文][4バイト長][AES暗号文])で書く" do
        bytes = decoded(legacy_encryptor.encrypt({ "user_id" => 1 }))

        expect(bytes.getbyte(0)).to eq(0)
      end

      it "認証鍵を持つ鍵では、読めないCookieを書かないようPqcRails::Errorを送出する" do
        expect { encryptor.encrypt({ "user_id" => 1 }) }.to raise_error(PqcRails::Error, /authentication key/)
      end

      it "期限が未設定でも過去でも、0.3.0の鍵で旧形式のCookieを読む" do
        [nil, Time.now - 60].each do |deadline|
          PqcRails.configuration.accept_legacy_cookies_until = deadline

          expect(legacy_encryptor.decrypt(legacy_encryptor.encrypt({ "user_id" => 1 }))).to eq({ "user_id" => 1 })
        end
      end

      it "新しい形式のCookieは、この設定でも読む" do
        PqcRails.configuration.ciphertext_format = :v1
        blob = encryptor.encrypt({ "user_id" => 2 })
        PqcRails.configuration.ciphertext_format = :v0

        expect(encryptor.decrypt(blob)).to eq({ "user_id" => 2 })
      end
    end

    it "期限が未設定なら、公開鍵だけで作った旧形式のCookieをMarshal.loadに渡さず拒否する" do
      forged = forge_legacy(keypair.public_key, { "user_id" => 1 })
      allow(Marshal).to receive(:load).and_call_original

      expect { legacy_encryptor.decrypt(forged) }.to raise_error(PqcRails::Error, /legacy/)
      expect(Marshal).not_to have_received(:load)
    end

    it "期限切れ・認証鍵で断れる旧形式のCookieでは、DBと同じ鍵かの確認(全モデルの走査)を走らせない" do
      forged = forge_legacy(keypair.public_key, { "user_id" => 1 })
      [legacy_encryptor, encryptor].each do |target|
        allow(target).to receive(:shared_with_records?).and_raise("the record key check must not run")
      end
      PqcRails.configuration.accept_legacy_cookies_until = Time.now - 60

      expect { legacy_encryptor.decrypt(forged) }.to raise_error(PqcRails::Error, /not accepted/)
      PqcRails.configuration.accept_legacy_cookies_until = Time.now + 60
      expect { encryptor.decrypt(forged) }.to raise_error(PqcRails::Error, /authentication key/)
    end

    it "認証鍵を持つ鍵宛の旧形式のCookieは、期限内でも:v0でもMarshal.loadに渡さず拒否する" do
      forged = forge_legacy(keypair.public_key, { "user_id" => 1 })
      allow(Marshal).to receive(:load).and_call_original

      [[:v1, Time.now + 60], [:v0, Time.now + 60], [:v0, nil]].each do |format, deadline|
        PqcRails.configuration.ciphertext_format = format
        PqcRails.configuration.accept_legacy_cookies_until = deadline

        expect { encryptor.decrypt(forged) }.to raise_error(PqcRails::Error, /authentication key/)
      end
      expect(Marshal).not_to have_received(:load)
    end

    context "セッションとDBに同じ0.3.0の鍵を設定しているとき" do
      around do |example|
        original = ENV.fetch("PQC_RECORD_KEY", nil), ENV.fetch("PQC_RECORD_PREVIOUS_KEYS", nil)
        example.run
      ensure
        ENV["PQC_RECORD_KEY"], ENV["PQC_RECORD_PREVIOUS_KEYS"] = original
      end

      it "DBの現行鍵と同じなら、期限内でも:v0でも旧形式のCookieをMarshal.loadに渡さず拒否する" do
        ENV["PQC_RECORD_KEY"] = PqcRails::KeySource.encode(legacy_keypair)
        ENV.delete("PQC_RECORD_PREVIOUS_KEYS")
        forged = forge_legacy(keypair.public_key, { "user_id" => 1 })
        allow(Marshal).to receive(:load).and_call_original

        [[:v1, Time.now + 60], [:v0, nil]].each do |format, deadline|
          PqcRails.configuration.ciphertext_format = format
          PqcRails.configuration.accept_legacy_cookies_until = deadline

          expect { legacy_encryptor.decrypt(forged) }.to raise_error(PqcRails::Error, /records/)
        end
        expect(Marshal).not_to have_received(:load)
      end

      it "DBの旧鍵と同じでも拒否する" do
        other = PqcRails::HybridKem.open(:ml_kem_512, &:generate_keypair)
        ENV["PQC_RECORD_KEY"] = PqcRails::KeySource.encode(other)
        ENV["PQC_RECORD_PREVIOUS_KEYS"] = PqcRails::KeySource.encode(legacy_keypair)
        PqcRails.configuration.accept_legacy_cookies_until = Time.now + 60

        expect { legacy_encryptor.decrypt(forge_legacy(keypair.public_key, { "user_id" => 1 })) }
          .to raise_error(PqcRails::Error, /records/)
      end

      it "ActiveRecord::Encryptionに設定した鍵ソースの鍵と同じでも拒否する" do
        ENV.delete("PQC_RECORD_KEY")
        ENV.delete("PQC_RECORD_PREVIOUS_KEYS")
        source = Struct.new(:current_keypair, :previous_keypairs).new(legacy_keypair, [])
        provider = PqcRails::ActiveRecord::KeyProvider.new(key_source: source)
        PqcRails.configuration.accept_legacy_cookies_until = Time.now + 60
        forged = forge_legacy(keypair.public_key, { "user_id" => 1 })

        ActiveRecord::Encryption.with_encryption_context(key_provider: provider) do
          expect { legacy_encryptor.decrypt(forged) }.to raise_error(PqcRails::Error, /records/)
        end
      end

      it "コンテキストの鍵ソースの判定を覚えず、範囲の外と中でそれぞれ判定する" do
        ENV.delete("PQC_RECORD_KEY")
        ENV.delete("PQC_RECORD_PREVIOUS_KEYS")
        source = Struct.new(:current_keypair, :previous_keypairs).new(legacy_keypair, [])
        provider = PqcRails::ActiveRecord::KeyProvider.new(key_source: source)
        PqcRails.configuration.accept_legacy_cookies_until = Time.now + 60
        forged = forge_legacy(keypair.public_key, { "user_id" => 1 })

        expect(legacy_encryptor.decrypt(forged)).to eq({ "user_id" => 1 })
        ActiveRecord::Encryption.with_encryption_context(key_provider: provider) do
          expect { legacy_encryptor.decrypt(forged) }.to raise_error(PqcRails::Error, /records/)
        end
        expect(legacy_encryptor.decrypt(forged)).to eq({ "user_id" => 1 })
      end

      it "install!の鍵ソースと同じ鍵は、別のコンテキストの中でも拒否する" do
        ENV.delete("PQC_RECORD_KEY")
        ENV.delete("PQC_RECORD_PREVIOUS_KEYS")
        source = Struct.new(:current_keypair, :previous_keypairs).new(legacy_keypair, [])
        other = Struct.new(:current_keypair, :previous_keypairs)
                      .new(PqcRails::HybridKem.open(:ml_kem_512, &:generate_keypair), [])
        original = PqcRails::ActiveRecord::KeyProvider.installed
        PqcRails::ActiveRecord::KeyProvider.installed = PqcRails::ActiveRecord::KeyProvider.new(key_source: source)
        PqcRails.configuration.accept_legacy_cookies_until = Time.now + 60
        forged = forge_legacy(keypair.public_key, { "user_id" => 1 })

        ActiveRecord::Encryption.with_encryption_context(
          key_provider: PqcRails::ActiveRecord::KeyProvider.new(key_source: other)
        ) do
          expect { legacy_encryptor.decrypt(forged) }.to raise_error(PqcRails::Error, /records/)
        end
      ensure
        PqcRails::ActiveRecord::KeyProvider.installed = original
      end

      it "公開鍵の文字コードが違っても、同じバイト列なら同じ鍵と判定する" do
        ENV.delete("PQC_RECORD_KEY")
        ENV.delete("PQC_RECORD_PREVIOUS_KEYS")
        utf8 = PqcRails::HybridKem::Keypair.new(keypair.public_key.dup.force_encoding(Encoding::UTF_8), keypair.secret_key)
        source = Struct.new(:current_keypair, :previous_keypairs).new(utf8, [])
        provider = PqcRails::ActiveRecord::KeyProvider.new(key_source: source)
        PqcRails.configuration.accept_legacy_cookies_until = Time.now + 60

        ActiveRecord::Encryption.with_encryption_context(key_provider: provider) do
          expect { legacy_encryptor.decrypt(forge_legacy(keypair.public_key, { "user_id" => 1 })) }
            .to raise_error(PqcRails::Error, /records/)
        end
      end

      it "DBと同じ鍵では、:v0でCookieを書くとPqcRails::Errorを送出する" do
        ENV["PQC_RECORD_KEY"] = PqcRails::KeySource.encode(legacy_keypair)
        PqcRails.configuration.ciphertext_format = :v0

        expect { legacy_encryptor.encrypt({ "user_id" => 1 }) }.to raise_error(PqcRails::Error, /records/)
      end

      context "属性ごとにkey_providerを指定したモデルがあるとき" do
        before(:all) do
          require_relative "../support/test_database"
          TestDatabase.connect
          ::ActiveRecord::Migration.verbose = false
          ::ActiveRecord::Schema.define do
            create_table(:legacy_cookie_widgets, force: true) { |t| t.text :secret }
          end
        end

        before do
          ENV["PQC_RECORD_KEY"] = PqcRails::KeySource.encode(PqcRails::HybridKem.open(:ml_kem_512, &:generate_keypair))
          ENV.delete("PQC_RECORD_PREVIOUS_KEYS")
          @models_before = ::ActiveRecord::Base.descendants
        end

        # 例ごとに作ったモデルを、後の例の判定に残さない。匿名のクラスはGCされるまでdescendantsに残るので、
        # 抽象クラスにして、属性ごとのkey_providerを集める対象(抽象クラスを除くモデル)から外す。
        after do
          (::ActiveRecord::Base.descendants - @models_before).each { |model| model.abstract_class = true }
        end

        def provider_for(keypair)
          PqcRails::ActiveRecord::KeyProvider.new(
            key_source: Struct.new(:current_keypair, :previous_keypairs).new(keypair, [])
          )
        end

        # 属性の型(暗号化のスキーム)を読み込んだモデルを返す。
        def attribute_model(provider, previous: false)
          Class.new(::ActiveRecord::Base) do
            self.table_name = "legacy_cookie_widgets"
            previous ? encrypts(:secret, previous: { key_provider: provider }) : encrypts(:secret, key_provider: provider)
          end.tap { |model| model.type_for_attribute(:secret) }
        end

        it "属性ごとのkey_providerの鍵と同じなら、期限内でも旧形式のCookieをMarshal.loadに渡さず拒否する" do
          attribute_model(provider_for(legacy_keypair))
          PqcRails.configuration.accept_legacy_cookies_until = Time.now + 60
          allow(Marshal).to receive(:load).and_call_original

          expect { legacy_encryptor.decrypt(forge_legacy(keypair.public_key, { "user_id" => 1 })) }
            .to raise_error(PqcRails::Error, /records/)
          expect(Marshal).not_to have_received(:load)
        end

        it "属性ごとのkey_providerの公開鍵の文字コードが違っても、同じバイト列なら拒否する" do
          utf8 = PqcRails::HybridKem::Keypair.new(legacy_keypair.public_key.dup.force_encoding(Encoding::UTF_8),
                                                  legacy_keypair.secret_key)
          attribute_model(provider_for(utf8))
          PqcRails.configuration.accept_legacy_cookies_until = Time.now + 60

          expect { legacy_encryptor.decrypt(forge_legacy(keypair.public_key, { "user_id" => 1 })) }
            .to raise_error(PqcRails::Error, /records/)
        end

        it "公開鍵を返さない独自のkey_providerを指定した属性があれば、比べられないので旧形式のCookieを拒否する" do
          attribute_model(Object.new)
          PqcRails.configuration.accept_legacy_cookies_until = Time.now + 60

          expect { legacy_encryptor.decrypt(forge_legacy(keypair.public_key, { "user_id" => 1 })) }
            .to raise_error(PqcRails::Error, /per-attribute/)
        end

        it "Rails標準のkey_providerを指定した属性は比べず、期限内は旧形式のCookieを読む" do
          attribute_model(::ActiveRecord::Encryption::KeyProvider.new(::ActiveRecord::Encryption::Key.new("a" * 32)))
          PqcRails.configuration.accept_legacy_cookies_until = Time.now + 60

          expect(legacy_encryptor.decrypt(forge_legacy(keypair.public_key, { "user_id" => 1 }))).to eq({ "user_id" => 1 })
        end

        it "Rails標準のkey_providerにpqc_railsの鍵ペアを入れた属性があれば、比べられないので旧形式のCookieを拒否する" do
          key = PqcRails::ActiveRecord::KeyProvider::Key.new(legacy_keypair)
          attribute_model(::ActiveRecord::Encryption::KeyProvider.new(key))
          PqcRails.configuration.accept_legacy_cookies_until = Time.now + 60

          expect { legacy_encryptor.decrypt(forge_legacy(keypair.public_key, { "user_id" => 1 })) }
            .to raise_error(PqcRails::Error, /per-attribute/)
        end

        it "Rails標準のkey_providerにpqc_railsの鍵ペアとAESの鍵を混ぜた属性があれば、AESの鍵が最後でも拒否する" do
          mixed = [PqcRails::ActiveRecord::KeyProvider::Key.new(legacy_keypair), ::ActiveRecord::Encryption::Key.new("a" * 32)]
          attribute_model(::ActiveRecord::Encryption::KeyProvider.new(mixed))
          PqcRails.configuration.accept_legacy_cookies_until = Time.now + 60

          expect { legacy_encryptor.decrypt(forge_legacy(keypair.public_key, { "user_id" => 1 })) }
            .to raise_error(PqcRails::Error, /per-attribute/)
        end

        it "属性ごとのprevious:に指定したkey_providerの鍵と同じでも拒否する" do
          attribute_model(provider_for(legacy_keypair), previous: true)
          PqcRails.configuration.accept_legacy_cookies_until = Time.now + 60

          expect { legacy_encryptor.decrypt(forge_legacy(keypair.public_key, { "user_id" => 1 })) }
            .to raise_error(PqcRails::Error, /records/)
        end

        it "属性ごとのkey_providerの鍵と同じなら、:v0でCookieを書くとPqcRails::Errorを送出する" do
          attribute_model(provider_for(legacy_keypair))
          PqcRails.configuration.ciphertext_format = :v0

          expect { legacy_encryptor.encrypt({ "user_id" => 1 }) }.to raise_error(PqcRails::Error, /records/)
        end

        it "属性ごとのkey_providerが別の鍵なら、期限内は旧形式のCookieを読む" do
          attribute_model(provider_for(PqcRails::HybridKem.open(:ml_kem_512, &:generate_keypair)))
          PqcRails.configuration.accept_legacy_cookies_until = Time.now + 60

          expect(legacy_encryptor.decrypt(forge_legacy(keypair.public_key, { "user_id" => 1 }))).to eq({ "user_id" => 1 })
        end

        it "旧形式のCookieを読む設定でない時は、属性ごとのkey_providerを集めない" do
          attribute_model(provider_for(legacy_keypair))
          PqcRails.configuration.accept_legacy_cookies_until = nil
          allow(PqcRails::ActiveRecord::KeyProvider).to receive(:per_attribute).and_call_original

          expect { legacy_encryptor.decrypt(forge_legacy(keypair.public_key, { "user_id" => 1 })) }
            .to raise_error(PqcRails::Error, /not accepted/)
          expect(PqcRails::ActiveRecord::KeyProvider).not_to have_received(:per_attribute)
        end

        it "テーブルの無いモデルは、属性ごとのkey_providerを比べずに旧形式のCookieを読む" do
          provider = provider_for(legacy_keypair)
          Class.new(::ActiveRecord::Base) do
            self.table_name = "legacy_cookie_missing_widgets"
            encrypts :secret, key_provider: provider
          end
          PqcRails.configuration.accept_legacy_cookies_until = Time.now + 60

          expect(legacy_encryptor.decrypt(forge_legacy(keypair.public_key, { "user_id" => 1 }))).to eq({ "user_id" => 1 })
        end

        it "DBに接続できないモデルがあれば、旧形式のCookieを拒否する" do
          model = attribute_model(provider_for(PqcRails::HybridKem.open(:ml_kem_512, &:generate_keypair)))
          allow(model).to receive(:table_exists?).and_raise(::ActiveRecord::ConnectionNotEstablished, "host=db.internal must-not-appear")
          PqcRails.configuration.accept_legacy_cookies_until = Time.now + 60

          expect { legacy_encryptor.decrypt(forge_legacy(keypair.public_key, { "user_id" => 1 })) }
            .to raise_error(PqcRails::Error, /could not compare.*ConnectionNotEstablished/) { |e|
              expect(e.full_message).not_to include("must-not-appear")
              expect(e.cause).to be_nil
            }
        end

        it "DBの接続が定義されていないモデルは、比べずに旧形式のCookieを読む" do
          model = attribute_model(provider_for(legacy_keypair))
          allow(model).to receive(:connection_specification_name).and_return("UndefinedConnection")
          PqcRails.configuration.accept_legacy_cookies_until = Time.now + 60

          expect(legacy_encryptor.decrypt(forge_legacy(keypair.public_key, { "user_id" => 1 }))).to eq({ "user_id" => 1 })
        end

        it "属性ごとのkey_providerを確かめられない時は、旧形式のCookieを拒否する" do
          PqcRails.configuration.accept_legacy_cookies_until = Time.now + 60
          allow(PqcRails::ActiveRecord::KeyProvider).to receive(:per_attribute)
            .and_raise(::ActiveRecord::StatementInvalid, "no such table")

          expect { legacy_encryptor.decrypt(forge_legacy(keypair.public_key, { "user_id" => 1 })) }
            .to raise_error(PqcRails::Error, /could not compare/)
        end
      end

      it "DBと別の鍵なら、期限内は旧形式のCookieを読む" do
        ENV["PQC_RECORD_KEY"] = PqcRails::KeySource.encode(PqcRails::HybridKem.open(:ml_kem_512, &:generate_keypair))
        ENV.delete("PQC_RECORD_PREVIOUS_KEYS")
        PqcRails.configuration.accept_legacy_cookies_until = Time.now + 60

        expect(legacy_encryptor.decrypt(forge_legacy(keypair.public_key, { "user_id" => 1 }))).to eq({ "user_id" => 1 })
      end
    end

    it "同じ鍵でも、DBカラムのv1暗号文をCookieの形に組み替えたものはMarshal.loadに届かない" do
      message = PqcRails::Cipher.new(pq_alg_name: :ml_kem_512).encrypt(Marshal.dump({ "user_id" => 1 }), key: keypair)
      algorithm_id = message.headers[:alg]
      header = [PqcRails::CiphertextFormat::VERSION, algorithm_id.bytesize].pack("CC") + algorithm_id +
               [message.headers[:kid]].pack("H4")
      cookie = Base64.strict_encode64(header + PqcRails::BlobPacking.pack(message.headers[:kem_ct], message.payload))
      allow(Marshal).to receive(:load).and_call_original

      expect { encryptor.decrypt(cookie) }.to raise_error(PqcRails::Error)
      expect(Marshal).not_to have_received(:load)
    end

    it "同じ鍵でも、Cookieのv1本体をDBカラムの暗号文に組み替えたものは復号できない" do
      bytes = decoded(encryptor.encrypt("value"))
      id_length = bytes.getbyte(1)
      kem_ciphertext, encrypted = PqcRails::BlobPacking.unpack(bytes[(4 + id_length)..], exact: true)
      message = ActiveRecord::Encryption::Message.new(payload: encrypted)
      message.headers[:kem_ct] = kem_ciphertext
      message.headers[:pv] = PqcRails::CiphertextFormat::VERSION
      message.headers[:alg] = bytes[2, id_length]
      message.headers[:kid] = bytes[2 + id_length, 2].unpack1("H4")

      expect { PqcRails::Cipher.new(pq_alg_name: :ml_kem_512).decrypt(message, key: keypair) }
        .to raise_error(ActiveRecord::Encryption::Errors::Decryption)
    end

    context "旧形式のCookieの受け付け期限(accept_legacy_cookies_until)" do
      let(:legacy_blob) do
        PqcRails.configuration.ciphertext_format = :v0
        legacy_encryptor.encrypt({ "user_id" => 1 }).tap { PqcRails.configuration.ciphertext_format = :v1 }
      end

      it "期限を過ぎたら旧形式のCookieを拒否する" do
        PqcRails.configuration.accept_legacy_cookies_until = Time.now - 60

        expect { legacy_encryptor.decrypt(legacy_blob) }.to raise_error(PqcRails::Error, /legacy/)
      end

      it "期限前は旧形式のCookieを読む" do
        PqcRails.configuration.accept_legacy_cookies_until = Time.now + 60

        expect(legacy_encryptor.decrypt(legacy_blob)).to eq({ "user_id" => 1 })
      end

      it "期限を過ぎても、新しい形式のCookieは読む" do
        PqcRails.configuration.accept_legacy_cookies_until = Time.now - 60

        expect(encryptor.decrypt(encryptor.encrypt({ "user_id" => 2 }))).to eq({ "user_id" => 2 })
      end
    end

    it "認証鍵を持たない鍵(0.3.0以前の形式)では新しい形式で暗号化できない" do
      legacy_key = PqcRails::HybridKem::Keypair.new(keypair.public_key, keypair.secret_key)

      expect { described_class.new(legacy_key, pq_alg_name: :ml_kem_512).encrypt({ "user_id" => 1 }) }
        .to raise_error(PqcRails::MissingAuthenticationKeyError)
    end
  end
end
