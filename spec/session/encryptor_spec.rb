# frozen_string_literal: true

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
      original_accept_legacy = PqcRails.configuration.accept_legacy_ciphertexts
      example.run
    ensure
      PqcRails.configuration.ciphertext_format = original_format
      PqcRails.configuration.accept_legacy_ciphertexts = original_accept_legacy
    end

    def decoded(blob) = Base64.strict_decode64(blob)

    # 公開鍵だけを使い、KEMの共有鍵をそのままAES鍵にしてv1形式のCookieを作る。
    # 秘密鍵を持たない者が作れるCookieに当たる。
    def forge_with_public_key(public_key, session)
      algorithm_id = PqcRails::CiphertextFormat.algorithm_id(:ml_kem_512)
      key_id = PqcRails::CiphertextFormat.key_id(public_key)
      associated_data = PqcRails::CiphertextFormat.associated_data(algorithm_id: algorithm_id, key_id: key_id)
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

    it "未知の形式バージョンはPqcRails::Errorを送出する" do
      bytes = decoded(encryptor.encrypt({ "user_id" => 1 }))
      bytes.setbyte(0, 2)

      expect { encryptor.decrypt(Base64.strict_encode64(bytes)) }.to raise_error(PqcRails::Error, /version/)
    end

    context "ciphertext_format = :v0 のとき" do
      before { PqcRails.configuration.ciphertext_format = :v0 }

      it "旧形式([4バイト長][KEM暗号文][4バイト長][AES暗号文])で書く" do
        bytes = decoded(encryptor.encrypt({ "user_id" => 1 }))

        expect(bytes.getbyte(0)).to eq(0)
      end
    end

    it "旧形式で書かれたCookieを、新形式で書く設定のまま復号できる" do
      PqcRails.configuration.ciphertext_format = :v0
      legacy_blob = encryptor.encrypt({ "user_id" => 1 })
      PqcRails.configuration.ciphertext_format = :v1

      expect(encryptor.decrypt(legacy_blob)).to eq({ "user_id" => 1 })
    end

    it "accept_legacy_ciphertexts = false のとき、旧形式のCookieを拒否する" do
      PqcRails.configuration.ciphertext_format = :v0
      legacy_blob = encryptor.encrypt({ "user_id" => 1 })
      PqcRails.configuration.ciphertext_format = :v1
      PqcRails.configuration.accept_legacy_ciphertexts = false

      expect { encryptor.decrypt(legacy_blob) }.to raise_error(PqcRails::Error, /legacy/)
    end
  end
end
