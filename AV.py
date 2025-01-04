import os
import math
import numpy as np
import torch
import torch.nn.functional as F
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import Dense, Embedding, LSTM, Dropout
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.utils import to_categorical

# Extract strings from an executable file
def extract_strings_from_exe(filepath, min_length=4):
    """
    Extracts strings from a binary executable file.
    Only strings longer than the specified minimum length will be returned.
    """
    try:
        with open(filepath, 'rb') as file:
            data = file.read()

        strings = []
        current_string = []

        for byte in data:
            # ASCII printable characters are in the range of 32-126
            if 32 <= byte <= 126:
                current_string.append(chr(byte))
            else:
                if len(current_string) >= min_length:
                    strings.append(''.join(current_string))
                current_string = []

        # Handle last string
        if len(current_string) >= min_length:
            strings.append(''.join(current_string))

        return strings
    except Exception as e:
        print(f"Error extracting strings from {filepath}: {e}")
        return []

# Prepare data for training the neural network
def prepare_data(strings, labels, max_len=100):
    """
    Convert strings to sequences of integers and pad them to a fixed length.
    """
    tokenizer = {char: idx + 1 for idx, char in enumerate(set(''.join(strings)))}
    tokenizer['<PAD>'] = 0  # Padding token
    
    sequences = [[tokenizer[char] for char in string] for string in strings]
    padded_sequences = pad_sequences(sequences, maxlen=max_len, padding='post', truncating='post')
    labels = np.array(labels)
    
    return padded_sequences, labels, tokenizer

# Build the neural network model
def build_model(input_shape, vocab_size):
    model = Sequential([
        Embedding(input_dim=vocab_size, output_dim=128, input_length=input_shape[1]),
        LSTM(128, return_sequences=True),
        Dropout(0.5),
        LSTM(64),
        Dense(32, activation='relu'),
        Dense(2, activation='softmax')  # 2 classes: benign and malicious
    ])
    model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
    return model

# Generate text with the trained model (for future extensions)
def generate_text(model, seed_text, word_to_index, index_to_word, vocab_size, sequence_length, num_words, temperature=1.0, device='cpu'):
    model.eval()
    model = model.to(device)

    # Process seed text
    words = seed_text.lower().split()
    if len(words) < sequence_length:
        raise ValueError(f"Seed text must contain at least {sequence_length} words")

    current_sequence = words[-sequence_length:]
    generated_words = []
    full_stop_count = 0  # To count full stops (periods)
    word_correlation = {}  # Dictionary to keep track of recent correlations
    with torch.no_grad():
        for _ in range(num_words):
            # Convert current sequence to tensor
            try:
                sequence_indices = [word_to_index[word] for word in current_sequence]
            except KeyError:
                print("Warning: Unknown word in seed text. Using random word from vocabulary.")
                sequence_indices = np.random.choice(list(index_to_word.keys()), sequence_length).tolist()

            sequence_tensor = torch.tensor([sequence_indices], dtype=torch.long)
            x = F.one_hot(sequence_tensor, num_classes=vocab_size).float()
            x = x.reshape(1, -1).to(device)

            # Get predictions
            logits = model(x)

            # Apply temperature
            scaled_logits = logits / temperature
            probs = F.softmax(scaled_logits, dim=-1)

            # Sample from the distribution
            next_word_idx = torch.multinomial(probs, 1).item()
            next_word = index_to_word[next_word_idx]

            generated_words.append(next_word)

            # Update sequence for next iteration
            current_sequence = current_sequence[1:] + [next_word]

    return ' '.join(generated_words)

# Main function to train and test the model
def main():
    # Step 1: Extract strings from executable files (you can replace these paths with actual file paths)
    exe_paths = ['AxInstUI.exe', 'bcdboot.exe']  # Add paths to your executable files
    labels = [0, 1]  # Example: 0 for benign, 1 for malicious

    all_strings = []
    for path in exe_paths:
        strings = extract_strings_from_exe(path)
        all_strings.extend(strings)

    # Step 2: Prepare the data
    X, y, tokenizer = prepare_data(all_strings, labels)

    # Step 3: Build and train the model
    model = build_model(X.shape, len(tokenizer))
    y = to_categorical(y, num_classes=2)  # Convert labels to one-hot encoding
    model.fit(X, y, epochs=10, batch_size=32)


    try:
        # Step 5: Load the saved model
        loaded_model = load_model('exe_scanner_model.h5')
        print("Model loaded successfully.")
    except:
        # Step 4: Save the model
        model.save('exe_scanner_model.h5')
        print("Model saved as 'exe_scanner_model.h5'")
    # Step 6: Use the loaded model for inference or further training
    scan_exe = "test.exe"
    strings = extract_strings_from_exe(scan_exe)

    # For example, classify a new executable (you can adjust how you input the strings)
    padded_strings, _, _ = prepare_data(strings, labels=[0], max_len=100)
    prediction = loaded_model.predict(padded_strings)
    print(f"Prediction (Benign=0, Malicious=1): {np.argmax(prediction)}")

if __name__ == "__main__":
    main()
