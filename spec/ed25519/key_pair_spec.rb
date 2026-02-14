# frozen_string_literal: true

require "spec_helper"

RSpec.describe Ed25519::KeyPair do
  let(:key_pair) { described_class.generate }
  let(:key_pair_with_comment) { described_class.generate(comment: "test@example.com") }

  describe ".generate" do
    it "generates a key pair" do
      expect(key_pair).to be_a described_class
      expect(key_pair.signing_key).to be_a Ed25519::SigningKey
      expect(key_pair.verify_key).to be_a Ed25519::VerifyKey
    end

    it "raises ArgumentError when passphrase is provided" do
      expect do
        described_class.generate(passphrase: "secret")
      end.to raise_error(ArgumentError, /passphrase encryption is not currently supported/)
    end
  end

  describe "#ssh_public_key" do
    it "returns a string in SSH public key format" do
      public_key = key_pair.ssh_public_key
      expect(public_key).to be_a String
      expect(public_key).to start_with("ssh-ed25519 ")
    end

    it "includes the comment when provided" do
      public_key = key_pair_with_comment.ssh_public_key
      expect(public_key).to end_with(" test@example.com")
    end

    it "produces a valid base64 encoded key" do
      public_key = key_pair.ssh_public_key
      parts = public_key.split
      expect(parts[0]).to eq("ssh-ed25519")

      # Verify base64 can be decoded
      expect { Base64.strict_decode64(parts[1]) }.not_to raise_error
    end

    it "includes the algorithm name and public key in the encoded data" do
      public_key = key_pair.ssh_public_key
      base64_part = public_key.split[1]
      decoded = Base64.strict_decode64(base64_part)

      # Parse the SSH key format
      pos = 0

      # Algorithm name length
      algo_len = decoded[pos..pos + 3].unpack1("N")
      pos += 4

      # Algorithm name
      algorithm = decoded[pos..pos + algo_len - 1]
      pos += algo_len
      expect(algorithm).to eq("ssh-ed25519")

      # Public key length
      key_len = decoded[pos..pos + 3].unpack1("N")
      pos += 4

      # Public key
      public_key_bytes = decoded[pos..pos + key_len - 1]
      expect(public_key_bytes).to eq(key_pair.verify_key.to_bytes)
    end
  end

  describe "#private_key" do
    it "returns a string in OpenSSH private key format" do
      private_key = key_pair.private_key
      expect(private_key).to be_a String
      expect(private_key).to start_with("-----BEGIN OPENSSH PRIVATE KEY-----\n")
      expect(private_key).to end_with("-----END OPENSSH PRIVATE KEY-----\n")
    end

    it "produces a valid base64 encoded key" do
      private_key = key_pair.private_key
      # Extract base64 content between header and footer
      lines = private_key.lines
      base64_content = lines[1..-2].join.strip

      # Verify base64 can be decoded
      expect { Base64.decode64(base64_content) }.not_to raise_error
    end

    it "contains the magic header in the decoded data" do
      private_key = key_pair.private_key
      lines = private_key.lines
      base64_content = lines[1..-2].join.strip
      decoded = Base64.decode64(base64_content)

      # Check for magic header "openssh-key-v1\0"
      expect(decoded[0..14]).to eq("openssh-key-v1\0")
    end

    it "includes the comment in the private key when provided" do
      private_key = key_pair_with_comment.private_key
      lines = private_key.lines
      base64_content = lines[1..-2].join.strip
      decoded = Base64.decode64(base64_content)

      # The comment should be present in the decoded data
      expect(decoded).to include("test@example.com")
    end

    it "creates a private key that contains the correct public and private key bytes" do
      private_key = key_pair.private_key
      lines = private_key.lines
      base64_content = lines[1..-2].join.strip
      decoded = Base64.decode64(base64_content)

      # The decoded data should contain both the signing key and verify key bytes
      expect(decoded).to include(key_pair.signing_key.to_bytes)
      expect(decoded).to include(key_pair.verify_key.to_bytes)
    end
  end

  describe "key pair compatibility" do
    it "can sign and verify messages using the generated keys" do
      message = "test message"

      # Sign with the signing key
      signature = key_pair.signing_key.sign(message)

      # Verify with the verify key
      expect { key_pair.verify_key.verify(signature, message) }.not_to raise_error
      expect(key_pair.verify_key.verify(signature, message)).to be true
    end
  end

  describe "integration with SigningKey" do
    it "can be created from an existing SigningKey" do
      signing_key = Ed25519::SigningKey.generate
      key_pair = described_class.new(signing_key, comment: "test")

      expect(key_pair.signing_key).to eq(signing_key)
      expect(key_pair.verify_key.to_bytes).to eq(signing_key.verify_key.to_bytes)
    end
  end
end
