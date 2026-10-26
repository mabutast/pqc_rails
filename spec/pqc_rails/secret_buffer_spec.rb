# frozen_string_literal: true

RSpec.describe PqcRails::SecretBuffer do
  describe ".with" do
    it "値を書き込んだバッファをブロックに渡し、ブロックの戻り値を返す" do
      result = described_class.with(4, "\x01\x02\x03\x04".b) { |pointer| pointer.read_bytes(4) }

      expect(result).to eq("\x01\x02\x03\x04".b)
    end

    it "ブロックを抜けたらバッファをゼロで埋める" do
      buffer = nil
      described_class.with(4, "\xFF\xFF\xFF\xFF".b) { |pointer| buffer = pointer }

      expect(buffer.read_bytes(4)).to eq("\x00" * 4)
    end

    it "ブロックで例外が出ても、バッファをゼロで埋める" do
      buffer = nil
      expect do
        described_class.with(4, "\xFF\xFF\xFF\xFF".b) do |pointer|
          buffer = pointer
          raise "boom"
        end
      end.to raise_error(RuntimeError, "boom")

      expect(buffer.read_bytes(4)).to eq("\x00" * 4)
    end
  end

  describe ".wipe" do
    it "文字列を同じオブジェクトのままゼロで上書きする" do
      secret = "\xAA".b * 64

      described_class.wipe(secret)

      expect(secret).to eq("\x00" * 64)
    end

    it "nilと凍結された文字列は飛ばす" do
      frozen = "secret".b.freeze

      expect { described_class.wipe(nil, frozen) }.not_to raise_error
      expect(frozen).to eq("secret")
    end
  end

  # liboqsに秘密鍵・共有鍵を渡す・受け取るCのバッファが、呼び出しの後に残らないことを確かめる。
  describe "Kem・Sigでの使われ方" do
    let(:pointers) { [] }

    before do
      original = FFI::MemoryPointer.method(:new)
      allow(FFI::MemoryPointer).to receive(:new) do |*args|
        original.call(*args).tap { |pointer| pointers << pointer }
      end
    end

    def secret_buffers(size)
      pointers.select { |pointer| pointer.size == size }
    end

    it "Kem#generate_keypair・#decapsulateの後、秘密鍵と共有鍵のバッファはゼロで埋まっている" do
      PqcRails::Kem.open(:ml_kem_768) do |kem|
        keypair = kem.generate_keypair
        encap = kem.encapsulate(keypair.public_key)
        pointers.clear
        kem.decapsulate(encap.ciphertext, keypair.secret_key)

        buffers = secret_buffers(kem.length_secret_key) + secret_buffers(kem.length_shared_secret)
        expect(buffers.size).to eq(2)
        buffers.each { |pointer| expect(pointer.read_bytes(pointer.size)).to eq("\x00" * pointer.size) }

        pointers.clear
        kem.generate_keypair
        expect(secret_buffers(kem.length_secret_key).map { |pointer| pointer.read_bytes(pointer.size) })
          .to eq(["\x00" * kem.length_secret_key])
      end
    end

    it "Sig#generate_keypair・#signの後、秘密鍵のバッファはゼロで埋まっている" do
      PqcRails::Sig.open(:ml_dsa_44) do |sig|
        keypair = sig.generate_keypair
        expect(secret_buffers(sig.length_secret_key).map { |pointer| pointer.read_bytes(pointer.size) })
          .to eq(["\x00" * sig.length_secret_key])

        pointers.clear
        sig.sign("message", keypair.secret_key)
        expect(secret_buffers(sig.length_secret_key).map { |pointer| pointer.read_bytes(pointer.size) })
          .to eq(["\x00" * sig.length_secret_key])
      end
    end
  end
end
