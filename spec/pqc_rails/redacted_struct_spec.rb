# frozen_string_literal: true

require "pp"
require "json"
require "yaml"
require "active_support"
require "active_support/json"

RSpec.describe "秘密の値を持つオブジェクトの表示" do
  # 表示の文字列に、秘密の値が生のバイト列・inspectのエスケープ・16進・Base64のどの形でも含まれないことを確かめる。
  def expect_not_to_reveal(output, secret)
    expect(output.b).not_to include(secret.b)
    expect(output).not_to include(secret.inspect[1..-2])
    expect(output.downcase).not_to include(secret.unpack1("H*"))
    expect(output).not_to include([secret].pack("m0"))
  end

  def outputs_of(keypair)
    {
      inspect: keypair.inspect,
      to_s: keypair.to_s,
      pretty_inspect: keypair.pretty_inspect,
      interpolation: "#{keypair}"
    }
  end

  # JSONにする主な経路の出力。入れ子にした場合も含める。
  def json_outputs_of(object)
    [
      object.as_json.to_s,
      object.to_json,
      ActiveSupport::JSON.encode(object),
      JSON.generate(object),
      JSON.pretty_generate(object),
      JSON.dump(object),
      [object].to_json,
      { value: object }.to_json,
      JSON.generate([object])
    ]
  end

  shared_examples "秘密鍵を伏せる鍵ペア" do |secret_members|
    it "inspect・to_s・pretty_inspectに秘密の値が含まれず、[FILTERED]と公開鍵の長さが出る" do
      outputs_of(keypair).each_value do |output|
        secret_members.each { |member| expect_not_to_reveal(output, keypair[member]) }
        expect_not_to_reveal(output, keypair.public_key)
        secret_members.each { |member| expect(output).to include("#{member}=[FILTERED]") }
        expect(output).to include("public_key=[#{keypair.public_key.bytesize} bytes]")
      end
    end

    it "as_json・to_json・JSON.generateは、公開鍵を長さ、秘密を[FILTERED]にする" do
      json = keypair.as_json

      expect(json.fetch("public_key")).to eq("[#{keypair.public_key.bytesize} bytes]")
      secret_members.each { |member| expect(json.fetch(member.to_s)).to eq("[FILTERED]") }
      json_outputs_of(keypair).each do |output|
        keypair.to_a.each { |value| expect_not_to_reveal(output, value) }
      end
    end

    it "値の取り出し・to_h・to_a・==は変わらない" do
      copy = keypair.class.new(*keypair.to_a.map(&:dup))
      other = keypair.class.new(*keypair.to_a.map { |value| value&.reverse })

      expect(copy).to eq(keypair)
      expect(other).not_to eq(keypair)
      expect(keypair.to_a).to eq(keypair.members.map { |member| keypair[member] })
      expect(keypair.to_h).to eq(keypair.members.to_h { |member| [member, keypair[member]] })
      expect(keypair.to_h.values).to all(satisfy { |value| value != "[FILTERED]" })
      # 読み出しメソッド(keypair.secret_keyなど)が、伏せた文字列ではなく元のバイト列を返す
      keypair.members.each_with_index do |member, index|
        expect(keypair.public_send(member)).to eq(keypair.to_a[index])
      end
    end
  end

  describe PqcRails::Sig::Keypair do
    let(:keypair) { PqcRails::Sig.open(:ml_dsa_44, &:generate_keypair) }

    it_behaves_like "秘密鍵を伏せる鍵ペア", %i[secret_key]
  end

  describe PqcRails::Kem::Keypair do
    let(:keypair) { PqcRails::Kem.open(:ml_kem_768, &:generate_keypair) }

    it_behaves_like "秘密鍵を伏せる鍵ペア", %i[secret_key]

    it "公開鍵が文字列でなくても、表示で例外を出さず[FILTERED]にする" do
      odd = described_class.new(123, keypair.secret_key)

      outputs_of(odd).each_value do |output|
        expect(output).to include("public_key=[FILTERED]")
        expect_not_to_reveal(output, keypair.secret_key)
      end
    end
  end

  describe PqcRails::DhKem::Keypair do
    let(:keypair) { PqcRails::DhKem.new.generate_keypair }

    it_behaves_like "秘密鍵を伏せる鍵ペア", %i[secret_key]
  end

  describe PqcRails::HybridKem::Keypair do
    let(:keypair) { PqcRails::HybridKem.open(:ml_kem_768, &:generate_keypair) }

    it_behaves_like "秘密鍵を伏せる鍵ペア", %i[secret_key authentication_key]

    it "認証鍵の無い0.3.0の鍵ペアは、認証鍵をnilと表示する" do
      legacy = described_class.new(keypair.public_key, keypair.secret_key, nil)

      expect(legacy.inspect).to include("authentication_key=nil")
      expect_not_to_reveal(legacy.inspect, keypair.secret_key)
    end
  end

  # 公開してよいメンバーを列挙する作りなので、後から増えた秘密のメンバーも伏せることを、名前の違うメンバーで確かめる。
  it "公開してよい一覧に無いメンバーは、名前に関係なく伏せる" do
    klass = Struct.new(:public_key, :seed) { include PqcRails::RedactedStruct }
    seed = Random.bytes(32)
    holder = klass.new(Random.bytes(16), seed)

    outputs_of(holder).each_value do |output|
      expect(output).to include("seed=[FILTERED]")
      expect_not_to_reveal(output, seed)
    end
    expect(holder.as_json["seed"]).to eq("[FILTERED]")
    (json_outputs_of(holder) + [holder.to_yaml]).each { |output| expect_not_to_reveal(output, seed) }
  end

  describe "Encapsulationの表示" do
    {
      PqcRails::Kem::Encapsulation => -> { PqcRails::Kem.open(:ml_kem_768) { |kem| kem.encapsulate(kem.generate_keypair.public_key) } },
      PqcRails::DhKem::Encapsulation => -> { PqcRails::DhKem.new.then { |kem| kem.encapsulate(kem.generate_keypair.public_key) } },
      PqcRails::HybridKem::Encapsulation => -> { PqcRails::HybridKem.open(:ml_kem_768) { |kem| kem.encapsulate(kem.generate_keypair.public_key) } }
    }.each do |klass, build|
      context klass.name do
        let(:encap) { build.call }

        it "inspect・to_s・ppで共有秘密を伏せ、暗号文は長さだけを出す" do
          outputs_of(encap).each_value do |output|
            expect_not_to_reveal(output, encap.shared_secret)
            expect_not_to_reveal(output, encap.ciphertext)
            expect(output).to include("shared_secret=[FILTERED]")
            expect(output).to include("ciphertext=[#{encap.ciphertext.bytesize} bytes]")
          end
        end

        it "as_json・to_json・JSON.generateに秘密の値が出ない" do
          expect(encap.as_json).to eq(
            "ciphertext" => "[#{encap.ciphertext.bytesize} bytes]", "shared_secret" => "[FILTERED]"
          )
          json_outputs_of(encap).each do |output|
            expect_not_to_reveal(output, encap.shared_secret)
            expect_not_to_reveal(output, encap.ciphertext)
          end
        end

        it "値の取り出し・to_h・to_a・==は変わらない" do
          copy = klass.new(encap.ciphertext.dup, encap.shared_secret.dup)
          other = klass.new(encap.ciphertext, encap.shared_secret.reverse)

          expect(copy).to eq(encap)
          expect(other).not_to eq(encap)
          expect(encap.to_a).to eq([encap.ciphertext, encap.shared_secret])
          expect(encap.to_h).to eq(ciphertext: encap.ciphertext, shared_secret: encap.shared_secret)
          expect(encap.shared_secret.encoding).to eq(Encoding::BINARY)
        end
      end
    end
  end

  describe "鍵ペアのJSON" do
    it "as_jsonのonly・methodsを指定しても秘密の値が出ない" do
      keypair = PqcRails::Kem.open(:ml_kem_768, &:generate_keypair)

      [{ only: :secret_key }, { methods: :secret_key }].each do |options|
        expect_not_to_reveal(keypair.as_json(options).to_s, keypair.secret_key)
      end
    end

    it "認証鍵の無い0.3.0の鍵ペアは、as_jsonで認証鍵をnilにする" do
      keypair = PqcRails::HybridKem.open(:ml_kem_768, &:generate_keypair)
      legacy = keypair.class.new(keypair.public_key, keypair.secret_key, nil)

      expect(legacy.as_json.fetch("authentication_key")).to be_nil
    end

    it "長さは文字数ではなくバイト数で出す" do
      multibyte = PqcRails::Kem::Encapsulation.new("あ", "secret")

      expect(multibyte.inspect).to include("ciphertext=[3 bytes]")
      expect(multibyte.as_json.fetch("ciphertext")).to eq("[3 bytes]")
    end

    it "公開鍵が文字列でなくても、as_jsonで値を出さず[FILTERED]にする" do
      odd = PqcRails::Kem::Keypair.new(123, "secret")

      expect(odd.as_json).to eq("public_key" => "[FILTERED]", "secret_key" => "[FILTERED]")
    end
  end

  describe PqcRails::EnvelopeCipher do
    let(:key) { OpenSSL::Random.random_bytes(32) }
    let(:cipher) { described_class.new(key) }

    it "inspect・to_s・ppに鍵のバイト列が出ない" do
      outputs_of(cipher).each_value { |output| expect_not_to_reveal(output, key) }
      expect(cipher.inspect).to eq("#<PqcRails::EnvelopeCipher key=[FILTERED]>")
    end

    it "as_json・to_json・JSON.generateに鍵のバイト列が出ない" do
      expect(cipher.as_json).to eq("key" => "[FILTERED]")
      json_outputs_of(cipher).each { |output| expect_not_to_reveal(output, key) }
    end
  end

  describe "YAML" do
    def expect_yaml_redacted(object, secrets)
      yaml = YAML.dump(object)

      secrets.each { |secret| expect_not_to_reveal(yaml.delete("\n "), secret) }
      expect(yaml).not_to include("!ruby", "!binary")
      expect(YAML.safe_load(yaml)).to eq(object.as_json)
    end

    {
      "Sig::Keypair" => -> { PqcRails::Sig.open(:ml_dsa_44, &:generate_keypair) },
      "Kem::Keypair" => -> { PqcRails::Kem.open(:ml_kem_768, &:generate_keypair) },
      "DhKem::Keypair" => -> { PqcRails::DhKem.new.generate_keypair },
      "HybridKem::Keypair" => -> { PqcRails::HybridKem.open(:ml_kem_768, &:generate_keypair) },
      "Kem::Encapsulation" => -> { PqcRails::Kem.open(:ml_kem_768) { |kem| kem.encapsulate(kem.generate_keypair.public_key) } },
      "DhKem::Encapsulation" => -> { PqcRails::DhKem.new.then { |kem| kem.encapsulate(kem.generate_keypair.public_key) } },
      "HybridKem::Encapsulation" => -> { PqcRails::HybridKem.open(:ml_kem_768) { |kem| kem.encapsulate(kem.generate_keypair.public_key) } }
    }.each do |name, build|
      context name do
        it "YAMLは秘密の値を出さず、クラスのタグの無いas_jsonと同じマップになる" do
          object = build.call

          expect_yaml_redacted(object, object.to_a)
        end
      end
    end

    it "EnvelopeCipherのYAMLは鍵を出さず、クラスのタグの無いマップになる" do
      key = OpenSSL::Random.random_bytes(32)

      expect_yaml_redacted(PqcRails::EnvelopeCipher.new(key), [key])
    end

    it "認証鍵の無い0.3.0の鍵ペアは、YAMLで認証鍵をnilにする" do
      keypair = PqcRails::HybridKem.open(:ml_kem_768, &:generate_keypair)
      legacy = keypair.class.new(keypair.public_key, keypair.secret_key, nil)

      expect(YAML.safe_load(YAML.dump(legacy)).fetch("authentication_key")).to be_nil
    end

    it "鍵ペアを内部に持つKeyProvider::KeyとSession::EncryptorのYAMLにも秘密の値が出ない" do
      keypair = PqcRails::HybridKem.open(:ml_kem_768, &:generate_keypair)

      [PqcRails::ActiveRecord::KeyProvider::Key.new(keypair), PqcRails::Session::Encryptor.new(keypair)].each do |owner|
        yaml = YAML.dump(owner).delete("\n ")
        [keypair.secret_key, keypair.authentication_key].each { |secret| expect_not_to_reveal(yaml, secret) }
      end
    end

  end

  describe "Marshal" do
    # Marshal.dumpがTypeErrorになり、メッセージに秘密の値が出ないことを確かめる。
    # 案内は鍵の置き場所(credentials・環境変数)と、置き場所だけを書き出すEnvCredentialsを指し、
    # 秘密鍵をそのまま含む文字列を作るKeySource.encodeは指さない(キャッシュ等に入れると鍵が残るため)。
    def expect_marshal_refused(object, secrets)
      expect { Marshal.dump(object) }.to raise_error(TypeError) { |error|
        secrets.compact.each { |secret| expect_not_to_reveal(error.message, secret) }
        expect(error.message).to include("Do not store it in caches, job arguments or files")
        expect(error.message).to include("Rails credentials or environment variables")
        expect(error.message).to include("PqcRails::KeySource::EnvCredentials")
        expect(error.message).not_to include("KeySource.encode")
      }
    end

    let(:hybrid_keypair) { PqcRails::HybridKem.open(:ml_kem_768, &:generate_keypair) }

    it "鍵ペアはどのアルゴリズムでもMarshal.dumpでTypeErrorを送出し、メッセージに秘密の値を含めない" do
      keypairs = [
        hybrid_keypair,
        PqcRails::Kem.open(:ml_kem_768, &:generate_keypair),
        PqcRails::DhKem.new.generate_keypair,
        PqcRails::Sig.open(:ml_dsa_65, &:generate_keypair)
      ]

      keypairs.each do |keypair|
        expect_marshal_refused(keypair, [keypair.secret_key, keypair.to_h[:authentication_key]])
      end
    end

    it "KEMの結果(Encapsulation)は3種類ともMarshal.dumpでTypeErrorを送出し、共有秘密を含めない" do
      kem_keypair = PqcRails::Kem.open(:ml_kem_768, &:generate_keypair)
      dh = PqcRails::DhKem.new
      encaps = [
        PqcRails::HybridKem.open(:ml_kem_768) { |kem| kem.encapsulate(hybrid_keypair.public_key) },
        PqcRails::Kem.open(:ml_kem_768) { |kem| kem.encapsulate(kem_keypair.public_key) },
        dh.encapsulate(dh.generate_keypair.public_key)
      ]

      encaps.each { |encap| expect_marshal_refused(encap, [encap.shared_secret]) }
    end

    it "配列・ハッシュに入れた鍵ペアもMarshal.dumpでTypeErrorを送出する" do
      [[hybrid_keypair], { key: hybrid_keypair }, [{ nested: [hybrid_keypair] }]].each do |container|
        expect_marshal_refused(container, [hybrid_keypair.secret_key, hybrid_keypair.authentication_key])
      end
    end

    it "AES鍵を持つEnvelopeCipherはMarshal.dumpでTypeErrorを送出し、鍵を含めない" do
      key = OpenSSL::Random.random_bytes(32)

      expect_marshal_refused(PqcRails::EnvelopeCipher.new(key), [key])
    end

    it "認証鍵の無い0.3.0の鍵ペアもMarshal.dumpでTypeErrorを送出する" do
      legacy = hybrid_keypair.class.new(hybrid_keypair.public_key, hybrid_keypair.secret_key, nil)

      expect_marshal_refused(legacy, [legacy.secret_key])
    end

    it "鍵ペアを内部に持つKeyProvider::KeyとSession::EncryptorもMarshal.dumpでTypeErrorを送出する" do
      owners = [PqcRails::ActiveRecord::KeyProvider::Key.new(hybrid_keypair), PqcRails::Session::Encryptor.new(hybrid_keypair)]

      owners.each do |owner|
        expect_marshal_refused(owner, [hybrid_keypair.secret_key, hybrid_keypair.authentication_key])
      end
    end

    it "Marshal以外(==・to_h・inspect)は変わらない" do
      copy = hybrid_keypair.class.new(*hybrid_keypair.to_a)

      expect(copy).to eq(hybrid_keypair)
      expect(copy.to_h[:secret_key]).to eq(hybrid_keypair.secret_key)
      expect(copy.inspect).to include("secret_key=[FILTERED]")
    end
  end
end
