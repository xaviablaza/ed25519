# frozen_string_literal: true

require "securerandom"
require "base64"

module Ed25519
  # Represents an Ed25519 key pair with methods to generate SSH format keys
  class KeyPair
    attr_reader :signing_key, :verify_key

    # Generate a new Ed25519 key pair
    #
    # @param comment [String] optional comment for the SSH key (e.g., "user@host.com")
    # @param passphrase [String] optional passphrase to encrypt the private key (not currently supported)
    #
    # @return [Ed25519::KeyPair] a new key pair instance
    def self.generate(comment: "", passphrase: nil)
      raise ArgumentError, "passphrase encryption is not currently supported" if passphrase

      signing_key = Ed25519::SigningKey.generate
      new(signing_key, comment: comment)
    end

    # Create a KeyPair from an existing SigningKey
    #
    # @param signing_key [Ed25519::SigningKey] the signing key
    # @param comment [String] optional comment for the SSH key
    def initialize(signing_key, comment: "")
      @signing_key = signing_key
      @verify_key = signing_key.verify_key
      @comment = comment
    end

    # Return the public key in SSH format
    #
    # @return [String] SSH format public key (e.g., "ssh-ed25519 AAAAC3NzaC1...")
    def ssh_public_key
      # SSH public key format: "ssh-ed25519 " + base64(string(algorithm) + string(public_key))
      algorithm = "ssh-ed25519"
      data = ""

      # Add algorithm name (4 bytes length + string)
      data += [algorithm.bytesize].pack("N")
      data += algorithm

      # Add public key (4 bytes length + 32 bytes key)
      public_key_bytes = @verify_key.to_bytes
      data += [public_key_bytes.bytesize].pack("N")
      data += public_key_bytes

      # Return formatted SSH public key
      result = "#{algorithm} #{Base64.strict_encode64(data)}"
      result += " #{@comment}" unless @comment.empty?
      result
    end

    # Return the private key in OpenSSH format
    #
    # @return [String] OpenSSH format private key (e.g., "-----BEGIN OPENSSH PRIVATE KEY-----...")
    def private_key
      openssh_key_blob = build_openssh_private_key_blob
      base64_encoded = Base64.strict_encode64(openssh_key_blob)

      # Format with 70 characters per line
      lines = base64_encoded.scan(/.{1,70}/)

      "-----BEGIN OPENSSH PRIVATE KEY-----\n" \
        "#{lines.join("\n")}\n" \
        "-----END OPENSSH PRIVATE KEY-----\n"
    end

    private

    # Build the OpenSSH private key blob according to the OpenSSH key format specification
    def build_openssh_private_key_blob
      data = ""

      # Magic header: "openssh-key-v1\0"
      data += "openssh-key-v1\0"

      # Cipher name (none for unencrypted)
      cipher = "none"
      data += [cipher.bytesize].pack("N")
      data += cipher

      # KDF name (none for unencrypted)
      kdf = "none"
      data += [kdf.bytesize].pack("N")
      data += kdf

      # KDF options (empty for unencrypted)
      data += [0].pack("N")

      # Number of keys (always 1)
      data += [1].pack("N")

      # Public key section
      public_key_section = build_public_key_section
      data += [public_key_section.bytesize].pack("N")
      data += public_key_section

      # Private key section
      private_key_section = build_private_key_section
      data += [private_key_section.bytesize].pack("N")
      data += private_key_section

      data
    end

    # Build the public key section for the OpenSSH format
    def build_public_key_section
      data = ""
      algorithm = "ssh-ed25519"

      # Algorithm name
      data += [algorithm.bytesize].pack("N")
      data += algorithm

      # Public key
      public_key_bytes = @verify_key.to_bytes
      data += [public_key_bytes.bytesize].pack("N")
      data += public_key_bytes

      data
    end

    # Build the private key section for the OpenSSH format
    def build_private_key_section
      data = ""
      algorithm = "ssh-ed25519"

      # Check integers (random, must be equal for unencrypted keys)
      check_int = SecureRandom.random_number(2**32)
      data += [check_int].pack("N")
      data += [check_int].pack("N")

      # Algorithm name
      data += [algorithm.bytesize].pack("N")
      data += algorithm

      # Public key
      public_key_bytes = @verify_key.to_bytes
      data += [public_key_bytes.bytesize].pack("N")
      data += public_key_bytes

      # Private key + public key (64 bytes for ed25519)
      # Ed25519 stores the 32-byte seed as private key, followed by 32-byte public key
      private_and_public = @signing_key.to_bytes + public_key_bytes
      data += [private_and_public.bytesize].pack("N")
      data += private_and_public

      # Comment
      data += [@comment.bytesize].pack("N")
      data += @comment

      # Padding (required to make the private key section a multiple of 8 bytes)
      # Padding bytes are sequential: 1, 2, 3, 4, 5, 6, 7, ...
      padding_length = (8 - (data.bytesize % 8)) % 8
      padding = (1..padding_length).to_a.pack("C*")
      data += padding

      data
    end
  end
end
