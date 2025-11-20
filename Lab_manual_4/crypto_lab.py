# crypto_lab.py
import os
import time
import struct
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP
import matplotlib.pyplot as plt

class CryptoLab:
    def __init__(self):
        self.aes_keys = {}
        self.rsa_keys = {}
        print("Crypto Lab initialized successfully!")
    
    # ==================== KEY MANAGEMENT ====================
    
    def generate_aes_key(self, key_size=128):
        """Generate AES key and save to file"""
        try:
            key = get_random_bytes(key_size // 8)
            filename = f"aes_key_{key_size}.bin"
            with open(filename, 'wb') as f:
                f.write(key)
            self.aes_keys[key_size] = key
            print(f"AES-{key_size} key generated and saved to {filename}")
            return key
        except Exception as e:
            print(f"Error generating AES key: {e}")
            return None
    
    def load_aes_key(self, key_size):
        """Load AES key from file"""
        try:
            filename = f"aes_key_{key_size}.bin"
            if os.path.exists(filename):
                with open(filename, 'rb') as f:
                    key = f.read()
                self.aes_keys[key_size] = key
                return key
            else:
                print(f"Key file not found. Generating new AES-{key_size} key...")
                return self.generate_aes_key(key_size)
        except Exception as e:
            print(f"Error loading AES key: {e}")
            return None
    
    def generate_rsa_keys(self, key_size=2048):
        """Generate RSA keys and save to files"""
        try:
            key = RSA.generate(key_size)
            private_key = key.export_key()
            public_key = key.publickey().export_key()
            
            # Save keys to files
            with open(f'private_rsa_{key_size}.pem', 'wb') as f:
                f.write(private_key)
            with open(f'public_rsa_{key_size}.pem', 'wb') as f:
                f.write(public_key)
            
            self.rsa_keys[key_size] = {
                'private': key,
                'public': key.publickey()
            }
            
            print(f"RSA-{key_size} keys generated and saved to files")
            return key
        except Exception as e:
            print(f"Error generating RSA keys: {e}")
            return None
    
    def load_rsa_keys(self, key_size=2048):
        """Load RSA keys from files"""
        try:
            if key_size in self.rsa_keys:
                return self.rsa_keys[key_size]
            
            private_file = f'private_rsa_{key_size}.pem'
            public_file = f'public_rsa_{key_size}.pem'
            
            if os.path.exists(private_file) and os.path.exists(public_file):
                with open(private_file, 'rb') as f:
                    private_key = RSA.import_key(f.read())
                with open(public_file, 'rb') as f:
                    public_key = RSA.import_key(f.read())
                
                self.rsa_keys[key_size] = {
                    'private': private_key,
                    'public': public_key
                }
                print(f"RSA-{key_size} keys loaded from files")
                return self.rsa_keys[key_size]
            else:
                print(f"RSA key files not found. Generating new RSA-{key_size} keys...")
                return self.generate_rsa_keys(key_size)
        except Exception as e:
            print(f"Error loading RSA keys: {e}")
            return None
    
    # ==================== AES ENCRYPTION/DECRYPTION ====================
    
    def aes_encrypt(self, plaintext, key_size=128, mode='ECB'):
        """AES encryption with different modes"""
        try:
            start_time = time.time()
            
            key = self.load_aes_key(key_size)
            if key is None:
                return None, None
            
            if mode.upper() == 'ECB':
                cipher = AES.new(key, AES.MODE_ECB)
                ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
            elif mode.upper() == 'CFB':
                iv = get_random_bytes(AES.block_size)
                cipher = AES.new(key, AES.MODE_CFB, iv=iv)
                ciphertext = iv + cipher.encrypt(plaintext)
            else:
                print("Unsupported mode. Use ECB or CFB.")
                return None, None
            
            # Save encrypted data to file
            filename = f"encrypted_aes_{key_size}_{mode}.bin"
            with open(filename, 'wb') as f:
                f.write(ciphertext)
            
            end_time = time.time()
            execution_time = end_time - start_time
            
            print(f"AES-{key_size} {mode} encryption completed in {execution_time:.6f} seconds")
            print(f"Encrypted data saved to {filename}")
            
            return execution_time, ciphertext
        except Exception as e:
            print(f"Error during AES encryption: {e}")
            return None, None
    
    def aes_decrypt(self, key_size=128, mode='ECB'):
        """AES decryption"""
        try:
            start_time = time.time()
            
            key = self.load_aes_key(key_size)
            if key is None:
                return None, None
            
            filename = f"encrypted_aes_{key_size}_{mode}.bin"
            
            if not os.path.exists(filename):
                print(f"Encrypted file {filename} not found!")
                return None, None
            
            with open(filename, 'rb') as f:
                ciphertext = f.read()
            
            if mode.upper() == 'ECB':
                cipher = AES.new(key, AES.MODE_ECB)
                plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            elif mode.upper() == 'CFB':
                iv = ciphertext[:AES.block_size]
                actual_ciphertext = ciphertext[AES.block_size:]
                cipher = AES.new(key, AES.MODE_CFB, iv=iv)
                plaintext = cipher.decrypt(actual_ciphertext)
            else:
                print("Unsupported mode. Use ECB or CFB.")
                return None, None
            
            end_time = time.time()
            execution_time = end_time - start_time
            
            print(f"AES-{key_size} {mode} decryption completed in {execution_time:.6f} seconds")
            
            return execution_time, plaintext.decode('utf-8')
        except Exception as e:
            print(f"Error during AES decryption: {e}")
            return None, None
    
    # ==================== RSA ENCRYPTION/DECRYPTION ====================
    
    def rsa_encrypt(self, plaintext, key_size=2048):
        """RSA encryption"""
        try:
            start_time = time.time()
            
            keys = self.load_rsa_keys(key_size)
            if keys is None:
                return None, None
            
            public_key = keys['public']
            
            # RSA can encrypt limited data, so we'll use PKCS1_OAEP for better security
            cipher_rsa = PKCS1_OAEP.new(public_key)
            encrypted_data = cipher_rsa.encrypt(plaintext)
            
            # Save encrypted data
            filename = f"encrypted_rsa_{key_size}.bin"
            with open(filename, 'wb') as f:
                f.write(encrypted_data)
            
            end_time = time.time()
            execution_time = end_time - start_time
            
            print(f"RSA-{key_size} encryption completed in {execution_time:.6f} seconds")
            print(f"Encrypted data saved to {filename}")
            
            return execution_time, encrypted_data
        except Exception as e:
            print(f"Error during RSA encryption: {e}")
            return None, None
    
    def rsa_decrypt(self, key_size=2048):
        """RSA decryption"""
        try:
            start_time = time.time()
            
            keys = self.load_rsa_keys(key_size)
            if keys is None:
                return None, None
            
            private_key = keys['private']
            
            filename = f"encrypted_rsa_{key_size}.bin"
            
            if not os.path.exists(filename):
                print(f"Encrypted file {filename} not found!")
                return None, None
            
            with open(filename, 'rb') as f:
                encrypted_data = f.read()
            
            cipher_rsa = PKCS1_OAEP.new(private_key)
            plaintext = cipher_rsa.decrypt(encrypted_data)
            
            end_time = time.time()
            execution_time = end_time - start_time
            
            print(f"RSA-{key_size} decryption completed in {execution_time:.6f} seconds")
            
            return execution_time, plaintext.decode('utf-8')
        except Exception as e:
            print(f"Error during RSA decryption: {e}")
            return None, None
    
    # ==================== RSA SIGNATURE ====================
    
    def rsa_sign(self, filename):
        """Generate RSA signature for a file"""
        try:
            start_time = time.time()
            
            if not os.path.exists(filename):
                print(f"File {filename} not found!")
                return None, None
            
            keys = self.load_rsa_keys(2048)  # Using 2048-bit for signatures
            if keys is None:
                return None, None
            
            private_key = keys['private']
            
            with open(filename, 'rb') as f:
                file_data = f.read()
            
            # Create hash of file
            file_hash = SHA256.new(file_data)
            
            # Sign the hash
            signature = pkcs1_15.new(private_key).sign(file_hash)
            
            # Save signature to file
            sig_filename = f"{filename}.sig"
            with open(sig_filename, 'wb') as f:
                f.write(signature)
            
            end_time = time.time()
            execution_time = end_time - start_time
            
            print(f"RSA signature generated in {execution_time:.6f} seconds")
            print(f"Signature saved to {sig_filename}")
            
            return execution_time, sig_filename
        except Exception as e:
            print(f"Error during RSA signing: {e}")
            return None, None
    
    def rsa_verify(self, filename, sig_filename):
        """Verify RSA signature"""
        try:
            start_time = time.time()
            
            if not os.path.exists(filename):
                print(f"File {filename} not found!")
                return None, None
            
            if not os.path.exists(sig_filename):
                print(f"Signature file {sig_filename} not found!")
                return None, None
            
            keys = self.load_rsa_keys(2048)
            if keys is None:
                return None, None
            
            public_key = keys['public']
            
            with open(filename, 'rb') as f:
                file_data = f.read()
            with open(sig_filename, 'rb') as f:
                signature = f.read()
            
            # Create hash of file
            file_hash = SHA256.new(file_data)
            
            # Verify signature
            try:
                pkcs1_15.new(public_key).verify(file_hash, signature)
                result = "✓ Signature is VALID"
            except (ValueError, TypeError):
                result = "✗ Signature is INVALID"
            
            end_time = time.time()
            execution_time = end_time - start_time
            
            print(f"RSA signature verification completed in {execution_time:.6f} seconds")
            
            return execution_time, result
        except Exception as e:
            print(f"Error during RSA verification: {e}")
            return None, None
    
    # ==================== SHA-256 HASHING ====================
    
    def sha256_hash(self, filename):
        """Generate SHA-256 hash of a file"""
        try:
            start_time = time.time()
            
            if not os.path.exists(filename):
                print(f"File {filename} not found!")
                return None, None
            
            with open(filename, 'rb') as f:
                file_data = f.read()
            
            file_hash = SHA256.new(file_data)
            hex_digest = file_hash.hexdigest()
            
            end_time = time.time()
            execution_time = end_time - start_time
            
            print(f"SHA-256 hash generated in {execution_time:.6f} seconds")
            
            return execution_time, hex_digest
        except Exception as e:
            print(f"Error during SHA-256 hashing: {e}")
            return None, None
    
    # ==================== PERFORMANCE MEASUREMENT ====================
    
    def measure_performance(self):
        """Measure execution time for different operations and key sizes"""
        print("\n" + "="*50)
        print("PERFORMANCE MEASUREMENT")
        print("="*50)
        
        # Test data of different sizes
        test_data_small = b"Hello, this is a test message!"  # 30 bytes
        test_data_medium = test_data_small * 10  # 300 bytes
        test_data_large = test_data_small * 100  # 3000 bytes
        
        test_cases = [
            (16, "16 bytes", test_data_small[:16]),
            (32, "32 bytes", test_data_small[:32]),
            (64, "64 bytes", test_data_medium[:64]),
            (128, "128 bytes", test_data_medium[:128]),
            (256, "256 bytes", test_data_large[:256])
        ]
        
        # AES Performance
        print("\n--- AES Performance ---")
        aes_enc_times_128 = []
        aes_dec_times_128 = []
        aes_enc_times_256 = []
        aes_dec_times_256 = []
        
        for size, label, data in test_cases:
            print(f"\nTesting with {label}:")
            
            # AES-128
            enc_time, _ = self.aes_encrypt(data, 128, 'ECB')
            if enc_time:
                aes_enc_times_128.append(enc_time)
            
            dec_time, _ = self.aes_decrypt(128, 'ECB')
            if dec_time:
                aes_dec_times_128.append(dec_time)
            
            # AES-256
            enc_time, _ = self.aes_encrypt(data, 256, 'ECB')
            if enc_time:
                aes_enc_times_256.append(enc_time)
            
            dec_time, _ = self.aes_decrypt(256, 'ECB')
            if dec_time:
                aes_dec_times_256.append(dec_time)
        
        # RSA Performance
        print("\n--- RSA Performance ---")
        rsa_key_sizes = [512, 1024, 2048, 3072, 4096]
        rsa_enc_times = []
        rsa_dec_times = []
        
        test_message = b"Test message for RSA"
        
        for key_size in rsa_key_sizes:
            print(f"\nTesting RSA-{key_size}:")
            
            try:
                # Generate temporary keys for this test
                temp_key = RSA.generate(key_size)
                public_key = temp_key.publickey()
                private_key = temp_key
                
                # Encryption
                start_time = time.time()
                cipher_rsa = PKCS1_OAEP.new(public_key)
                encrypted = cipher_rsa.encrypt(test_message)
                enc_time = time.time() - start_time
                rsa_enc_times.append(enc_time)
                
                # Decryption
                start_time = time.time()
                cipher_rsa = PKCS1_OAEP.new(private_key)
                decrypted = cipher_rsa.decrypt(encrypted)
                dec_time = time.time() - start_time
                rsa_dec_times.append(dec_time)
                
                print(f"  Encryption: {enc_time:.6f}s, Decryption: {dec_time:.6f}s")
                
            except Exception as e:
                print(f"  Failed to test RSA-{key_size}: {e}")
                rsa_enc_times.append(0)
                rsa_dec_times.append(0)
        
        # Plot results
        self.plot_performance_results(
            [size for size, _, _ in test_cases],
            aes_enc_times_128, aes_dec_times_128,
            aes_enc_times_256, aes_dec_times_256,
            rsa_key_sizes, rsa_enc_times, rsa_dec_times
        )
    
    def plot_performance_results(self, data_sizes, 
                               aes128_enc_times, aes128_dec_times,
                               aes256_enc_times, aes256_dec_times,
                               rsa_key_sizes, rsa_enc_times, rsa_dec_times):
        """Plot performance graphs"""
        try:
            fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
            
            # AES-128 Performance
            ax1.plot(data_sizes[:len(aes128_enc_times)], aes128_enc_times, 'b-o', label='Encryption', linewidth=2)
            ax1.plot(data_sizes[:len(aes128_dec_times)], aes128_dec_times, 'r-o', label='Decryption', linewidth=2)
            ax1.set_title('AES-128 Performance vs Data Size', fontsize=14, fontweight='bold')
            ax1.set_xlabel('Data Size (bytes)', fontsize=12)
            ax1.set_ylabel('Time (seconds)', fontsize=12)
            ax1.legend()
            ax1.grid(True, alpha=0.3)
            
            # AES-256 Performance
            ax2.plot(data_sizes[:len(aes256_enc_times)], aes256_enc_times, 'b-o', label='Encryption', linewidth=2)
            ax2.plot(data_sizes[:len(aes256_dec_times)], aes256_dec_times, 'r-o', label='Decryption', linewidth=2)
            ax2.set_title('AES-256 Performance vs Data Size', fontsize=14, fontweight='bold')
            ax2.set_xlabel('Data Size (bytes)', fontsize=12)
            ax2.set_ylabel('Time (seconds)', fontsize=12)
            ax2.legend()
            ax2.grid(True, alpha=0.3)
            
            # RSA Encryption Performance
            ax3.plot(rsa_key_sizes[:len(rsa_enc_times)], rsa_enc_times, 'g-o', linewidth=2)
            ax3.set_title('RSA Encryption Time vs Key Size', fontsize=14, fontweight='bold')
            ax3.set_xlabel('Key Size (bits)', fontsize=12)
            ax3.set_ylabel('Time (seconds)', fontsize=12)
            ax3.grid(True, alpha=0.3)
            
            # RSA Decryption Performance
            ax4.plot(rsa_key_sizes[:len(rsa_dec_times)], rsa_dec_times, 'm-o', linewidth=2)
            ax4.set_title('RSA Decryption Time vs Key Size', fontsize=14, fontweight='bold')
            ax4.set_xlabel('Key Size (bits)', fontsize=12)
            ax4.set_ylabel('Time (seconds)', fontsize=12)
            ax4.grid(True, alpha=0.3)
            
            plt.tight_layout()
            plt.savefig('crypto_performance.png', dpi=300, bbox_inches='tight')
            print(f"\nPerformance graphs saved to 'crypto_performance.png'")
            plt.show()
            
        except Exception as e:
            print(f"Error plotting graphs: {e}")
            print("Make sure matplotlib is installed: pip install matplotlib")
    
    # ==================== MENU SYSTEM ====================
    
    def show_menu(self):
        """Display main menu"""
        print("\n" + "="*50)
        print("          CRYPTO LAB PROGRAM")
        print("="*50)
        print("1. AES Encryption/Decryption")
        print("2. RSA Encryption/Decryption")
        print("3. RSA Signature")
        print("4. SHA-256 Hash")
        print("5. Performance Measurement")
        print("6. Exit")
        print("="*50)
    
    def aes_menu(self):
        """AES operations menu"""
        print("\n--- AES Operations ---")
        
        # Key size selection
        key_size = input("Enter key size (128 or 256): ").strip()
        if key_size not in ['128', '256']:
            print("Invalid key size! Using 128-bit.")
            key_size = '128'
        key_size = int(key_size)
        
        # Mode selection
        mode = input("Enter mode (ECB or CFB): ").strip().upper()
        if mode not in ['ECB', 'CFB']:
            print("Invalid mode! Using ECB.")
            mode = 'ECB'
        
        # Operation selection
        operation = input("Encrypt or Decrypt? (E/D): ").strip().upper()
        
        if operation == 'E':
            plaintext = input("Enter text to encrypt: ").encode('utf-8')
            time_taken, result = self.aes_encrypt(plaintext, key_size, mode)
            if time_taken is not None:
                print(f"✓ Encryption completed successfully!")
        elif operation == 'D':
            time_taken, result = self.aes_decrypt(key_size, mode)
            if time_taken is not None and result is not None:
                print(f"✓ Decryption completed successfully!")
                print(f"Decrypted text: {result}")
        else:
            print("Invalid operation! Please enter E or D.")
    
    def rsa_menu(self):
        """RSA operations menu"""
        print("\n--- RSA Operations ---")
        
        operation = input("Encrypt or Decrypt? (E/D): ").strip().upper()
        
        if operation == 'E':
            plaintext = input("Enter text to encrypt: ").encode('utf-8')
            time_taken, result = self.rsa_encrypt(plaintext, 2048)
            if time_taken is not None:
                print(f"✓ Encryption completed successfully!")
        elif operation == 'D':
            time_taken, result = self.rsa_decrypt(2048)
            if time_taken is not None and result is not None:
                print(f"✓ Decryption completed successfully!")
                print(f"Decrypted text: {result}")
        else:
            print("Invalid operation! Please enter E or D.")
    
    def signature_menu(self):
        """RSA signature menu"""
        print("\n--- RSA Signature ---")
        
        operation = input("Sign or Verify? (S/V): ").strip().upper()
        
        if operation == 'S':
            filename = input("Enter filename to sign: ").strip()
            time_taken, result = self.rsa_sign(filename)
            if time_taken is not None:
                print(f"✓ Signing completed successfully!")
        elif operation == 'V':
            filename = input("Enter filename to verify: ").strip()
            sig_filename = input("Enter signature filename: ").strip()
            time_taken, result = self.rsa_verify(filename, sig_filename)
            if time_taken is not None:
                print(f"Verification result: {result}")
        else:
            print("Invalid operation! Please enter S or V.")
    
    def hash_menu(self):
        """SHA-256 hash menu"""
        print("\n--- SHA-256 Hash ---")
        
        filename = input("Enter filename to hash: ").strip()
        time_taken, result = self.sha256_hash(filename)
        
        if time_taken is not None and result is not None:
            print(f"✓ Hash generated successfully!")
            print(f"SHA-256 Hash: {result}")
    
    def run(self):
        """Main program loop"""
        print("Welcome to Crypto Lab!")
        print("Initializing cryptographic components...")
        
        # Pre-load keys
        self.load_aes_key(128)
        self.load_aes_key(256)
        self.load_rsa_keys(2048)
        
        while True:
            self.show_menu()
            choice = input("Enter your choice (1-6): ").strip()
            
            try:
                if choice == '1':
                    self.aes_menu()
                elif choice == '2':
                    self.rsa_menu()
                elif choice == '3':
                    self.signature_menu()
                elif choice == '4':
                    self.hash_menu()
                elif choice == '5':
                    self.measure_performance()
                elif choice == '6':
                    print("\nThank you for using Crypto Lab! Goodbye! 👋")
                    break
                else:
                    print("Invalid choice! Please enter a number between 1-6.")
            except KeyboardInterrupt:
                print("\n\nProgram interrupted by user. Goodbye!")
                break
            except Exception as e:
                print(f"An error occurred: {e}")
            
            input("\nPress Enter to continue...")

# ==================== MAIN EXECUTION ====================

def main():
    """Main function"""
    try:
        # Check if required libraries are installed
        try:
            from Crypto.Cipher import AES, PKCS1_OAEP
            from Crypto.PublicKey import RSA
            from Crypto.Signature import pkcs1_15
            from Crypto.Hash import SHA256
        except ImportError as e:
            print("Error: Required cryptography libraries not found!")
            print("Please install them using: pip install pycryptodome")
            return
        
        # Create and run the crypto lab
        lab = CryptoLab()
        lab.run()
        
    except KeyboardInterrupt:
        print("\n\nProgram terminated by user.")
    except Exception as e:
        print(f"Fatal error: {e}")

if __name__ == "__main__":
    main()