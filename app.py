import hashlib

LEFT = "left"
RIGHT = "right"

data = ["data1", "data2", "data3", "data4", "data5", "data6"]


# Computes SHA-256 hash of the input data
def sha256(data):
    return hashlib.sha256(data.encode()).hexdigest()


# Ensures the number of hashes is even by duplicating the last hash if necessary
def ensure_even(hashes):
    if len(hashes) % 2 != 0:
        hashes.append(hashes[-1])


# Recursively generates the Merkle root from the list of hashes
def generate_merkle_root(hashes):
    if not hashes:
        return ""
    ensure_even(hashes)
    combined_hashes = []
    for i in range(0, len(hashes), 2):
        combined_hashes.append(sha256(hashes[i] + hashes[i + 1]))
    if len(combined_hashes) == 1:
        return combined_hashes[0]
    return generate_merkle_root(combined_hashes)


# Builds the Merkle tree as a list of lists, where each sublist represents a tree level
def generate_merkle_tree(hashes):
    if not hashes:
        return []
    tree = [hashes]
    while len(tree[-1]) > 1:
        current_level = tree[-1]
        ensure_even(current_level)
        next_level = [
            sha256(current_level[i] + current_level[i + 1])
            for i in range(0, len(current_level), 2)
        ]
        tree.append(next_level)
    return tree


# Determines whether the given hash is a left or right node in the Merkle tree
def get_leaf_node_direction(hash, merkle_tree):
    try:
        hash_index = merkle_tree[0].index(hash)
    except ValueError:
        return None
    return LEFT if hash_index % 2 == 0 else RIGHT


# Generates the Merkle proof for a given hash
def generate_merkle_proof(hash, hashes):
    if not hash or not hashes:
        return None
    tree = generate_merkle_tree(hashes)
    direction = get_leaf_node_direction(hash, tree)
    if direction is None:
        print("Hash not found in the Merkle tree.")
        return None

    proof = [{"hash": hash, "direction": direction}]
    hash_index = tree[0].index(hash)
    for level in range(len(tree) - 1):
        is_left_child = hash_index % 2 == 0
        sibling_index = hash_index + 1 if is_left_child else hash_index - 1
        sibling_direction = RIGHT if is_left_child else LEFT
        sibling_hash = tree[level][sibling_index]
        proof.append({"hash": sibling_hash, "direction": sibling_direction})
        hash_index //= 2
    return proof


# Calculates the Merkle root from the provided Merkle proof
def get_merkle_root_from_proof(proof):
    if not proof:
        return ""
    current_hash = proof[0]["hash"]
    for item in proof[1:]:
        if item["direction"] == RIGHT:
            current_hash = sha256(current_hash + item["hash"])
        else:
            current_hash = sha256(item["hash"] + current_hash)
    return current_hash


# Convert data to hashes
hashes = [sha256(d) for d in data]

# Generate Merkle root
merkle_root = generate_merkle_root(hashes)
print("Merkle Root:", merkle_root)

# Generate Merkle tree
merkle_tree = generate_merkle_tree(hashes)
print("Merkle Tree:", merkle_tree)

# Test with a hash that exists ('data2')
hash_data2 = sha256("data2")
generated_merkle_proof = generate_merkle_proof(hash_data2, hashes)
if generated_merkle_proof:
    print('Generated Merkle Proof for "data2":', generated_merkle_proof)
    merkle_root_from_proof = get_merkle_root_from_proof(generated_merkle_proof)
    print("Merkle Root from Merkle Proof:", merkle_root_from_proof)
    print(
        "Merkle Root from Merkle Proof === Merkle Root:",
        merkle_root_from_proof == merkle_root,
    )

# Test with a hash that does not exist ('data30')
hash_data30 = sha256("data30")
generated_merkle_proof = generate_merkle_proof(hash_data30, hashes)
if generated_merkle_proof:
    print('Generated Merkle Proof for "data30":', generated_merkle_proof)
    merkle_root_from_proof = get_merkle_root_from_proof(generated_merkle_proof)
    print("Merkle Root from Merkle Proof:", merkle_root_from_proof)
    print(
        "Merkle Root from Merkle Proof === Merkle Root:",
        merkle_root_from_proof == merkle_root,
    )
