from .sp_network import SP_Network
from .differential_cryptanalysis import DifferentialCryptanalysis

# Set the keys
keys = [1, 2, 3, 4, 516]

# Set permutation table
permutation = dict([(1, 1), (2, 5), (3, 9), (4, 13), (5, 2), (6, 6),
                    (7, 10), (8, 14), (9, 3), (10, 7), (11, 11), (12, 15),
                    (13, 4), (14, 8), (15, 12), (16, 16)])

# Set substitution table
substitution = dict([(0, 14), (1, 4), (2, 13), (3, 1), (4, 2), (5, 15), (6, 11),
                     (7, 8), (8, 3), (9, 10), (10, 6), (11, 12), (12, 5),
                     (13, 9), (14, 0), (15, 7)])
# Set plain text
plaintext = 782

# Create the SP Network using the keys, substitutions and permutations
sp_network = SP_Network(keys, substitution, permutation)

# Encrypt the plaintext
encryption = sp_network.encrypt(plaintext)

# Decrypt the ciphertext
decryption = sp_network.decrypt(encryption)

print('Plaintext: ', plaintext)
print('Encryption: ', encryption)
print('Decryption: ', decryption)

"""## Differential Cryptanalysis"""

# Initialize the DifferentialCryptanalysis with the SP Network created
dc_analysis = DifferentialCryptanalysis(sp_network)

# Calculate the difference distribution for the SP Network
dc_analysis.calculate_difference_distribution()

# Print the obtained difference distribution
dc_analysis.print_difference_distribution()

# Get the max delta x, delta y and the corresponding frequency
delta_x, delta_y, frequency = dc_analysis.get_max_frequency_difference()

print("\nMax ΔX: ", delta_x)
print("Max ΔY: ", delta_y)
print("Frequency: ", frequency)

# Set target sbox to attack
TARGET_SBOX = 2

# Get the delta p value corresponding to the target sbox
delta_p = dc_analysis.get_delta_p(delta_x, TARGET_SBOX)

# Get the last round input value and the probability of getting to it
u_comp, probability = dc_analysis.get_differential_characteristic(delta_p)

print("\nΔP: ", delta_p)
print("Last round input (U4): ", u_comp)
print("Probability of U4: ", probability)

# Generate random ciphertext pairs
pairs = dc_analysis.generate_plaintext_and_ciphertext_pairs(delta_p, 1000)

# Perform attack using the ciphertext pairs, differential characteristic and last round input value
subkey = dc_analysis.perform_attack(pairs, u_comp)

# Extract the valid subkey bits
subkey_bits = dc_analysis.extract_subkey_bits(subkey)

# Get the active sboxes of the last round
active_sboxes = dc_analysis.get_active_sboxes(u_comp)

# Convert the bits to binary string representation
subkey_bits_binary = dc_analysis.get_binary_rep_of_subkey(
    subkey, active_sboxes)

print("\nSubkey Guess: ", subkey)
print("Subkey Bits (list): ", subkey_bits)
print("Subkey Bits (binary): ", subkey_bits_binary)