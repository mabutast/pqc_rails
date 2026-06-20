# frozen_string_literal: true

require_relative "lib/pqc_rails"

PqcRails::Sig.open("ML-DSA-44") do |sig|
  puts "alg_name: #{sig.alg_name}"
  puts "length_public_key: #{sig.length_public_key}"
  puts "length_secret_key: #{sig.length_secret_key}"
  puts "length_signature:  #{sig.length_signature}"

  keypair = sig.generate_keypair
  puts "keypair generated. public_key bytesize=#{keypair.public_key.bytesize}, secret_key bytesize=#{keypair.secret_key.bytesize}"

  message = "Hello, post-quantum world!"
  signature = sig.sign(message, keypair.secret_key)
  puts "signed. signature bytesize=#{signature.bytesize} (max=#{sig.length_signature})"

  # パターン1: 正しい署名・正しいメッセージ・正しい公開鍵 → true になるはず
  valid = sig.verify(message, signature, keypair.public_key)
  puts "verify(correct message/signature/public_key): #{valid} (expected: true)"

  # パターン2: メッセージを改竄 → false になるはず
  tampered = sig.verify("Tampered message!", signature, keypair.public_key)
  puts "verify(tampered message): #{tampered} (expected: false)"

  # パターン3: 別の鍵ペアの公開鍵で検証 → false になるはず
  other_keypair = sig.generate_keypair
  wrong_key = sig.verify(message, signature, other_keypair.public_key)
  puts "verify(wrong public_key): #{wrong_key} (expected: false)"

  if valid && !tampered && !wrong_key
    puts "OK: all verify scenarios behaved as expected"
  else
    puts "NG: verify behaved unexpectedly"
  end
end
