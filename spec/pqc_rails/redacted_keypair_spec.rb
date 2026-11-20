# frozen_string_literal: true

require "pp"

RSpec.describe "鍵ペア(Keypair)の表示" do
  # 表示の文字列に、秘密の値のバイト列(生のままか、inspectのエスケープした形)が含まれないことを確かめる。
  def expect_not_to_reveal(output, secret)
    expect(output.b).not_to include(secret.b)
    expect(output).not_to include(secret.inspect[1..-2])
  end

  def outputs_of(keypair)
    {
      inspect: keypair.inspect,
      to_s: keypair.to_s,
      pretty_inspect: keypair.pretty_inspect,
      interpolation: "#{keypair}"
    }
  end

  shared_examples "秘密鍵を伏せる鍵ペア" do |secret_members|
    it "inspect・to_s・pretty_inspectに秘密の値が含まれず、[FILTERED]と公開鍵の長さが出る" do
      outputs_of(keypair).each_value do |output|
        secret_members.each { |member| expect_not_to_reveal(output, keypair[member]) }
        expect_not_to_reveal(output, keypair.public_key)
        expect(output).to include("[FILTERED]")
        expect(output).to include("#{keypair.public_key.bytesize} bytes")
      end
    end

    it "値の取り出し・to_a・==は変わらない" do
      copy = keypair.class.new(*keypair.to_a.map(&:dup))

      expect(copy).to eq(keypair)
      expect(keypair.to_a).to eq(keypair.members.map { |member| keypair[member] })
      secret_members.each { |member| expect(keypair[member]).to be_a(String) }
      expect(keypair.secret_key.bytesize).to be > 0
    end
  end

  describe PqcRails::Sig::Keypair do
    let(:keypair) { PqcRails::Sig.open(:ml_dsa_44, &:generate_keypair) }

    it_behaves_like "秘密鍵を伏せる鍵ペア", %i[secret_key]
  end

  describe PqcRails::Kem::Keypair do
    let(:keypair) { PqcRails::Kem.open(:ml_kem_768, &:generate_keypair) }

    it_behaves_like "秘密鍵を伏せる鍵ペア", %i[secret_key]
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
end
