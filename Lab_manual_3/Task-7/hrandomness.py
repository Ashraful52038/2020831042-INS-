#!/usr/bin/env python3

def hex_to_binary(hex_str):
    """Convert hexadecimal string to binary string"""
    return bin(int(hex_str, 16))[2:].zfill(len(hex_str) * 4)

def count_bit_difference(hash1, hash2):
    """Count how many bits are different between two hashes"""
    bin1 = hex_to_binary(hash1)
    bin2 = hex_to_binary(hash2)
    
    # Make sure both have same length
    max_len = max(len(bin1), len(bin2))
    bin1 = bin1.zfill(max_len)
    bin2 = bin2.zfill(max_len)
    
    diff_count = sum(bit1 != bit2 for bit1, bit2 in zip(bin1, bin2))
    total_bits = len(bin1)
    similarity = ((total_bits - diff_count) / total_bits) * 100
    
    return diff_count, total_bits, similarity

print("=== Hash Bit Difference Calculator ===")
print("MD5 and SHA256 Hash Comparison")

# আপনার ACTUAL hash values এখানে দিন
# MD5 Hashes
md5_hash1 = "9b6e56346f08294540fa27d3c28e3790"  # Original MD5
md5_hash2 = "852c985b6387affe714be8a7f508a810"  # Modified MD5

# SHA256 Hashes (আপনার actual SHA256 hash দিয়ে replace করুন)
sha256_hash1 = "17309a8644c4b4e4335e1d62cdec7a137e8ff85e754f530f044dd675a6b84e1c"  # Original SHA256
sha256_hash2 = "42066d0b8e645ac452031aab763c81a2e560b849b163ef6fafa7b8563be91336"  # Modified SHA256

print("\n" + "="*60)
print("MD5 HASH COMPARISON:")
print("="*60)
md5_diff, md5_total, md5_similarity = count_bit_difference(md5_hash1, md5_hash2)
print(f"Original MD5:  {md5_hash1}")
print(f"Modified MD5:  {md5_hash2}")
print(f"Total bits:    {md5_total}")
print(f"Different bits: {md5_diff}")
print(f"Same bits:     {md5_total - md5_diff}")
print(f"Similarity:    {md5_similarity:.6f}%")
print(f"Difference:    {100-md5_similarity:.6f}%")

print("\n" + "="*60)
print("SHA256 HASH COMPARISON:")
print("="*60)
sha256_diff, sha256_total, sha256_similarity = count_bit_difference(sha256_hash1, sha256_hash2)
print(f"Original SHA256:  {sha256_hash1}")
print(f"Modified SHA256:  {sha256_hash2}")
print(f"Total bits:       {sha256_total}")
print(f"Different bits:   {sha256_diff}")
print(f"Same bits:        {sha256_total - sha256_diff}")
print(f"Similarity:       {sha256_similarity:.6f}%")
print(f"Difference:       {100-sha256_similarity:.6f}%")

print("\n" + "="*60)
print("SUMMARY:")
print("="*60)
print(f"MD5 - Bits changed:    {md5_diff}/{md5_total} ({100-md5_similarity:.2f}%)")
print(f"SHA256 - Bits changed: {sha256_diff}/{sha256_total} ({100-sha256_similarity:.2f}%)")