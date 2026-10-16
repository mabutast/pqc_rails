# frozen_string_literal: true

require "active_record"

RSpec.describe PqcRails::Cipher do
  let(:keypair) { PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair } }
  let(:cipher)  { described_class.new(pq_alg_name: :ml_kem_512) }

  describe "#encrypt" do
    it "ActiveRecord::Encryption::Messageを返し、KEMのciphertextをheadersに持つ" do
      message = cipher.encrypt("hello", key: keypair)

      expect(message).to be_a(ActiveRecord::Encryption::Message)
      expect(message.payload).to be_a(String)
      expect(message.headers[:kem_ct]).to be_a(String)
    end

    it "deterministic: trueを渡すとArgumentErrorを送出する(KEMはランダム化されるためサポートしない)" do
      expect do
        cipher.encrypt("hello", key: keypair, deterministic: true)
      end.to raise_error(ArgumentError, /deterministic/)
    end
  end

  describe "#encrypt / #decrypt" do
    it "ラウンドトリップできる" do
      message = cipher.encrypt("hello pqc", key: keypair)

      expect(cipher.decrypt(message, key: keypair)).to eq("hello pqc")
    end

    it "Railsのkey:インターフェースに準拠し、keyが配列でも復号できる(鍵ローテーション互換)" do
      other_keypair = PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair }
      message = cipher.encrypt("hello pqc", key: keypair)

      expect(cipher.decrypt(message, key: [other_keypair, keypair])).to eq("hello pqc")
    end

    it "異なる鍵では復号できず、ActiveRecord::Encryption::Errors::Decryptionを送出する" do
      other_keypair = PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair }
      message = cipher.encrypt("hello pqc", key: keypair)

      expect do
        cipher.decrypt(message, key: other_keypair)
      end.to raise_error(ActiveRecord::Encryption::Errors::Decryption)
    end

    it "kem_ctヘッダーが無いMessageを復号しようとすると、NoMethodErrorではなくActiveRecord::Encryption::Errors::Decryptionを送出する" do
      malformed_message = ActiveRecord::Encryption::Message.new(payload: "not-a-real-payload")

      expect do
        cipher.decrypt(malformed_message, key: keypair)
      end.to raise_error(ActiveRecord::Encryption::Errors::Decryption)
    end
  end

  describe "暗号文のメタデータ(形式バージョン・アルゴリズムID・鍵ID)" do
    around do |example|
      original = PqcRails.configuration.ciphertext_format
      example.run
    ensure
      PqcRails.configuration.ciphertext_format = original
    end

    it "形式バージョン・アルゴリズムID・鍵IDをheadersに書く" do
      message = cipher.encrypt("hello", key: keypair)

      expect(message.headers[:pv]).to eq(1)
      expect(message.headers[:alg]).to eq("X25519+ML-KEM-512")
      expect(message.headers[:kid]).to eq(PqcRails::CiphertextFormat.key_id(keypair.public_key))
    end

    it "ActiveRecordのMessageSerializerを通しても復号できる(DBに保存して読み戻す経路)" do
      serializer = ActiveRecord::Encryption::MessageSerializer.new
      stored = serializer.dump(cipher.encrypt("hello pqc", key: keypair))

      expect(cipher.decrypt(serializer.load(stored), key: keypair)).to eq("hello pqc")
    end

    it "暗号文に書かれたアルゴリズムで復号する(設定のアルゴリズムを変えても既存データを読める)" do
      keypair_1024 = PqcRails::HybridKem.open(:ml_kem_1024) { |hybrid| hybrid.generate_keypair }
      message = described_class.new(pq_alg_name: :ml_kem_1024).encrypt("hello pqc", key: keypair_1024)

      expect(cipher.decrypt(message, key: [keypair, keypair_1024])).to eq("hello pqc")
    end

    it "アルゴリズムをliboqs名で設定しても、シンボルで設定したCipherと互いに復号できる" do
      message = described_class.new(pq_alg_name: "ML-KEM-512").encrypt("hello pqc", key: keypair)

      expect(cipher.decrypt(message, key: keypair)).to eq("hello pqc")
    end

    it "アルゴリズムIDを書き換えると復号できない" do
      message = cipher.encrypt("hello pqc", key: keypair)
      message.headers.instance_variable_get(:@data)[:alg] = "X25519+ML-KEM-768"

      expect do
        cipher.decrypt(message, key: keypair)
      end.to raise_error(ActiveRecord::Encryption::Errors::Decryption)
    end

    it "鍵IDを書き換えると復号できない" do
      message = cipher.encrypt("hello pqc", key: keypair)
      message.headers.instance_variable_get(:@data)[:kid] = "0000"

      expect do
        cipher.decrypt(message, key: keypair)
      end.to raise_error(ActiveRecord::Encryption::Errors::Decryption)
    end

    it "鍵IDが一致しない鍵では復号を試みない" do
      other_keypair = PqcRails::HybridKem.open(:ml_kem_512) { |hybrid| hybrid.generate_keypair }
      message = cipher.encrypt("hello pqc", key: keypair)
      allow(PqcRails::HybridKem).to receive(:open).and_call_original

      expect(cipher.decrypt(message, key: [other_keypair, keypair])).to eq("hello pqc")
      expect(PqcRails::HybridKem).to have_received(:open).once
    end

    it "レジストリ未登録で設定とも異なるアルゴリズムIDは拒否する" do
      message = cipher.encrypt("hello pqc", key: keypair)
      message.headers.instance_variable_get(:@data)[:alg] = "X25519+HQC-1"

      expect do
        cipher.decrypt(message, key: keypair)
      end.to raise_error(ActiveRecord::Encryption::Errors::Decryption)
    end

    context "ciphertext_format = :v0 のとき" do
      before { PqcRails.configuration.ciphertext_format = :v0 }

      it "旧形式(kem_ctヘッダーのみ)で書く" do
        message = cipher.encrypt("hello", key: keypair)

        expect(message.headers[:pv]).to be_nil
        expect(message.headers[:alg]).to be_nil
        expect(message.headers[:kid]).to be_nil
      end
    end

    it "旧形式で書かれたデータを、新形式で書く設定のまま復号できる" do
      PqcRails.configuration.ciphertext_format = :v0
      legacy_message = cipher.encrypt("hello pqc", key: keypair)
      PqcRails.configuration.ciphertext_format = :v1

      expect(cipher.decrypt(legacy_message, key: keypair)).to eq("hello pqc")
    end
  end

  describe "#key_length / #iv_length" do
    it "EnvelopeCipherが使うAES-256-GCMの鍵長・IV長を返す(ActiveRecord::Encryption::KeyGeneratorが要求するインターフェース)" do
      expect(cipher.key_length).to eq(PqcRails::EnvelopeCipher::KEY_LENGTH)
      expect(cipher.iv_length).to eq(PqcRails::EnvelopeCipher::IV_LENGTH)
    end
  end
end
