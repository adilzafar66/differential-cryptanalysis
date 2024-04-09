class SP_Network:
    """
    Class implementing an SP network encryption scheme.

    Attributes:
        keys (list): List of round keys.
        substitution (dict): Substitution dictionary for S-box.
        permutation (dict): Permutation dictionary for P-box.
        inv_substitution (dict): Inverse substitution dictionary for S-box.
        rounds (int): Number of encryption rounds.
        data_size (int): Size of the input data.

    Methods:
        keymix(round_num: int, input_data: int) -> int:
            Performs the key mixing operation.
        sbox(input_data: int, invert: bool) -> int:
            Performs substitution using the S-box.
        permute(input_data: int) -> int:
            Performs permutation using the P-box.
        substitute(input_data: int, invert: bool = False) -> int:
            Performs substitution using the S-box.
        encrypt(plain: int) -> int:
            Encrypts the plaintext.
        decrypt(cipher: int) -> int:
            Decrypts the ciphertext.
    """

    def __init__(self, keys: list, substitution: dict, permutation: dict):
        """
        Initializes the SP_Network object.

        Args:
            keys (list): List of round keys.
            substitution (dict): Substitution dictionary for S-box.
            permutation (dict): Permutation dictionary for P-box.

        Raises:
            ValueError: If substitution and permutation dictionaries are of different sizes.
        """
        if len(substitution) != len(permutation):
            raise ValueError(
                'Substitution and permutation dictionaries must be of the same size.')

        self.keys = keys
        self.substitution = substitution
        self.inv_substitution = {v: k for k, v in substitution.items()}
        self.permutation = permutation
        self.rounds = len(keys) - 1
        self.data_size = len(substitution)

    def keymix(self, round_num: int, input_data: int) -> int:
        """
        Performs the key mixing operation.

        Args:
            round_num (int): Round number.
            input_data (int): Input data.

        Returns:
            int: Result of key mixing operation.
        """
        return self.keys[round_num] ^ input_data

    def sbox(self, input_data: int, invert: bool = False) -> int:
        """
        Performs substitution using the S-box.

        Args:
            input_data (int): Input data.
            invert (bool): Whether to perform inversion.

        Returns:
            int: Substituted output.
        """
        sbox_dict = self.inv_substitution if invert else self.substitution
        return sbox_dict.get(input_data, 0)

    def permute(self, input_data: int) -> int:
        """
        Performs permutation using the P-box.

        Args:
            input_data (int): Input data.

        Returns:
            int: Permuted output.
        """
        output_data = 0
        for i in range(1, self.data_size + 1):
            output_data |= ((input_data >> (self.data_size -
                            self.permutation[i])) & 1) << (self.data_size - i)
        return output_data

    def substitute(self, input_data: int, invert: bool = False) -> int:
        """
        Performs substitution using the S-box.

        Args:
            input_data (int): Input data.
            invert (bool): Whether to perform inversion.

        Returns:
            int: Substituted output.
        """
        output_data = 0
        for i in range(0, self.data_size, 4):
            group = (input_data >> (self.data_size - i - 4)) & 0xF
            sbox_result = self.sbox(group, invert)
            output_data = (output_data << 4) | sbox_result
        return output_data

    def run_round(self, index: int, input_data: int):
        """
        Executes a single encryption round of the SP network.

        Args:
            index (int): Index of the round.
            input_data (int): Input data to the round.

        Returns:
            int: Output data after the round.
        """
        buffer = self.keymix(index, input_data)
        buffer = self.substitute(buffer)
        return self.permute(buffer)

    def run_reverse_round(self, index: int, input_data: int):
        """
        Executes a single decryption round of the SP network in reverse.

        Args:
            index (int): Index of the round.
            input_data (int): Input data to the round.

        Returns:
            int: Output data after the round.
        """
        buffer = self.permute(input_data)
        buffer = self.substitute(buffer, True)
        return self.keymix(index, buffer)

    def run_last_round(self, input_data):
        """
        Executes the final encryption round of the SP network.

        Args:
            input_data (int): Input data to the last round.

        Returns:
            int: Output data after the last round.
        """
        buffer = self.keymix(self.rounds - 1, input_data)
        buffer = self.substitute(buffer)
        return self.keymix(self.rounds, buffer)

    def run_reverse_last_round(self, input_data):
        """
        Executes the first decryption round of the SP network.

        Args:
            input_data (int): Input data to the first round.

        Returns:
            int: Output data after the first round.
        """
        buffer = self.keymix(self.rounds, input_data)
        buffer = self.substitute(buffer, True)
        return self.keymix(self.rounds - 1, buffer)

    def encrypt(self, plain: int) -> int:
        """
        Encrypts the plaintext.

        Args:
            plain (int): Plaintext to encrypt.

        Returns:
            int: Encrypted ciphertext.
        """
        buffer = plain
        for i in range(self.rounds - 1):
            buffer = self.run_round(i, buffer)
        buffer = self.run_last_round(buffer)
        return buffer

    def decrypt(self, cipher: int) -> int:
        """
        Decrypts the ciphertext.

        Args:
            cipher (int): Ciphertext to decrypt.

        Returns:
            int: Decrypted plaintext.
        """
        buffer = self.run_reverse_last_round(cipher)
        for i in range(self.rounds - 2, -1, -1):
            buffer = self.run_reverse_round(i, buffer)
        return buffer