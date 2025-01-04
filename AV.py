import os
import math
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F
from torch.utils.data import DataLoader, Dataset
from sklearn.preprocessing import LabelEncoder
from torch.utils.data import DataLoader
from typing import List, Dict, Tuple
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ExeScanner:
    def __init__(self, max_len: int = 100, min_string_length: int = 4):
        self.max_len = max_len
        self.min_string_length = min_string_length
        self.tokenizer = None
        self.model = None
        
    def extract_strings_from_exe(self, filepath: str) -> List[str]:
        """
        Extracts strings from a binary executable file.
        
        Args:
            filepath (str): Path to the executable file
            
        Returns:
            List[str]: Extracted strings longer than min_string_length
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")
            
        try:
            with open(filepath, 'rb') as file:
                data = file.read()

            strings = []
            current_string = []

            for byte in data:
                if 32 <= byte <= 126:
                    current_string.append(chr(byte))
                else:
                    if len(current_string) >= self.min_string_length:
                        strings.append(''.join(current_string))
                    current_string = []

            if len(current_string) >= self.min_string_length:
                strings.append(''.join(current_string))

            return strings
            
        except Exception as e:
            logging.error(f"Error extracting strings from {filepath}: {e}")
            raise

    def prepare_data(self, strings: List[str], labels: List[int]) -> Tuple[np.ndarray, np.ndarray, Dict[str, int]]:
        """
        Convert strings to sequences of integers and pad them.
        
        Args:
            strings (List[str]): List of extracted strings
            labels (List[int]): List of corresponding labels
            
        Returns:
            Tuple containing padded sequences, labels, and tokenizer
        """
        if not strings or not labels:
            raise ValueError("Empty strings or labels provided")
            
        # Create vocabulary from all unique characters
        unique_chars = set(''.join(strings))
        self.tokenizer = {char: idx + 1 for idx, char in enumerate(unique_chars)}
        self.tokenizer['<PAD>'] = 0
        
        # Convert strings to sequences
        sequences = [[self.tokenizer.get(char, 0) for char in string] for string in strings]
        
        # Pad sequences
        padded_sequences = np.array([
            sequence[:self.max_len] + [0] * (self.max_len - len(sequence)) 
            for sequence in sequences
        ])
        
        return padded_sequences, np.array(labels), self.tokenizer

class ExeDataset(Dataset):
    def __init__(self, strings: np.ndarray, labels: np.ndarray):
        """
        Custom Dataset for executable file analysis.
        
        Args:
            strings (np.ndarray): Padded sequences of tokenized strings
            labels (np.ndarray): Corresponding labels
        """
        self.strings = torch.tensor(strings, dtype=torch.long)
        self.labels = torch.tensor(labels, dtype=torch.long)
        
    def __len__(self) -> int:
        return len(self.strings)
    
    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, torch.Tensor]:
        if idx >= len(self.strings):
            raise IndexError(f"Index {idx} out of range for dataset of size {len(self.strings)}")
        return self.strings[idx], self.labels[idx]

class ExeScannerModel(nn.Module):
    def __init__(self, vocab_size: int, input_length: int, embedding_dim: int = 128):
        """
        Neural network model for executable file analysis.
        
        Args:
            vocab_size (int): Size of the vocabulary
            input_length (int): Length of input sequences
            embedding_dim (int): Dimension of embedding layer
        """
        super(ExeScannerModel, self).__init__()
        self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=0)
        self.lstm1 = nn.LSTM(embedding_dim, embedding_dim, batch_first=True, dropout=0.5)
        self.lstm2 = nn.LSTM(embedding_dim, 64, batch_first=True, dropout=0.5)
        self.fc1 = nn.Linear(64, 32)
        self.fc2 = nn.Linear(32, 2)
        
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.embedding(x)
        x, _ = self.lstm1(x)
        x, _ = self.lstm2(x)
        x = x[:, -1, :]  # Use the last LSTM output
        x = F.relu(self.fc1(x))
        x = self.fc2(x)
        return F.softmax(x, dim=1)

def train_model(
    model: nn.Module,
    train_loader: DataLoader,
    criterion: nn.Module,
    optimizer: optim.Optimizer,
    device: torch.device,
    num_epochs: int = 10
) -> List[float]:
    """
    Train the model and return training losses.
    
    Args:
        model: The neural network model
        train_loader: DataLoader for training data
        criterion: Loss function
        optimizer: Optimization algorithm
        device: Device to train on (CPU/GPU)
        num_epochs: Number of training epochs
        
    Returns:
        List of training losses per epoch
    """
    model.train()
    model.to(device)
    losses = []
    
    for epoch in range(num_epochs):
        running_loss = 0.0
        for inputs, targets in train_loader:
            inputs, targets = inputs.to(device), targets.to(device)
            
            optimizer.zero_grad()
            outputs = model(inputs)
            loss = criterion(outputs, targets)
            loss.backward()
            optimizer.step()
            
            running_loss += loss.item()
        
        epoch_loss = running_loss / len(train_loader)
        losses.append(epoch_loss)
        logging.info(f"Epoch [{epoch+1}/{num_epochs}], Loss: {epoch_loss:.4f}")
    
    return losses
def load_exe_paths_and_labels(clean_file_path: str, dirty_file_path: str) -> Tuple[List[str], List[int]]:
    """
    Load executable paths from two separate files and assign labels (0 for clean, 1 for dirty).
    
    Args:
        clean_file_path (str): Path to the file containing executable paths of clean files.
        dirty_file_path (str): Path to the file containing executable paths of dirty files.
        
    Returns:
        Tuple of (exe_paths, labels) where:
            - exe_paths is a list of paths from both clean and dirty files.
            - labels is a list of integers, 0 for clean, 1 for dirty.
    """
    try:
        # Load clean executable paths
        with open(clean_file_path, 'r') as clean_file:
            clean_paths = [line.strip() for line in clean_file.readlines()]
        
        # Load dirty executable paths
        with open(dirty_file_path, 'r') as dirty_file:
            dirty_paths = [line.strip() for line in dirty_file.readlines()]
        
        # Assign labels: 0 for clean, 1 for dirty
        labels = [0] * len(clean_paths) + [1] * len(dirty_paths)
        
        # Combine clean and dirty paths
        exe_paths = clean_paths + dirty_paths
        
        logging.info(f"Loaded {len(exe_paths)} executable paths with labels.")
        return exe_paths, labels
    
    except Exception as e:
        logging.error(f"Error loading executable paths and labels: {e}")
        raise

def main():
    # Configuration settings
    clean_file_path = 'clean.txt'  # Path to the clean executables list
    dirty_file_path = 'dirty.txt'  # Path to the dirty (malicious) executables list
    max_len = 100  # Maximum length of tokenized sequences
    min_string_length = 4  # Minimum length of strings to extract
    batch_size = 32  # Batch size for training
    num_epochs = 10  # Number of epochs to train
    learning_rate = 0.001  # Learning rate for the optimizer
    model_save_path = 'models/exe_scanner_model.pth'  # Path to save the model
    tokenizer_save_path = 'models/tokenizer.json'  # Path to save the tokenizer

    # Initialize ExeScanner instance
    scanner = ExeScanner(max_len=max_len, min_string_length=min_string_length)
    
    try:
        # Load executable paths and labels from clean.txt and dirty.txt
        exe_paths, labels = load_exe_paths_and_labels(clean_file_path, dirty_file_path)
        
        # Extract strings from executables
        all_strings = []
        for path in exe_paths:
            strings = scanner.extract_strings_from_exe(path)
            all_strings.extend(strings)
        
        # Prepare data (tokenize strings and create sequences)
        X, y, tokenizer = scanner.prepare_data(all_strings, labels)
        
        # Create Dataset and DataLoader for training
        dataset = ExeDataset(X, y)
        train_loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
        
        # Initialize the model and move it to the selected device (GPU/CPU)
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model = ExeScannerModel(vocab_size=len(tokenizer), input_length=max_len)
        model = model.to(device)
        
        # Set up the loss function and optimizer
        criterion = nn.CrossEntropyLoss()
        optimizer = optim.Adam(model.parameters(), lr=learning_rate)
        
        # Load existing model if available (to resume training)
        start_epoch = 0
        if os.path.exists(model_save_path):
            try:
                model, optimizer, start_epoch = scanner.load_model(model, model_save_path, optimizer)
                logging.info(f"Resumed training from epoch {start_epoch}")
            except Exception as e:
                logging.warning(f"Could not load existing model, starting fresh: {e}")
        
        # Train the model for the specified number of epochs
        for epoch in range(start_epoch, num_epochs):
            # Train for one epoch
            train_model(model, train_loader, criterion, optimizer, device, num_epochs=1)
            
            # Save the model checkpoint and tokenizer after each epoch
            try:
                scanner.save_model(model, model_save_path, optimizer, epoch + 1)
                scanner.save_tokenizer(tokenizer_save_path)
            except Exception as e:
                logging.error(f"Failed to save checkpoint: {e}")
        
        # Perform prediction with the trained model (using a sample test executable)
        test_file = "alg.exe"
        if os.path.exists(test_file):
            try:
                model.eval()
                test_strings = scanner.extract_strings_from_exe(test_file)
                test_sequences, _, _ = scanner.prepare_data(test_strings, [0] * len(test_strings))  # Assuming 0 for benign
                test_tensor = torch.tensor(test_sequences, dtype=torch.long).to(device)
                
                with torch.no_grad():
                    predictions = model(test_tensor)
                    predicted_labels = torch.argmax(predictions, dim=1)
                    logging.info(f"Predictions (Benign=0, Malicious=1): {predicted_labels.cpu().numpy()}")
                    
            except Exception as e:
                logging.error(f"Error during prediction: {e}")
                
    except Exception as e:
        logging.error(f"An error occurred in main: {e}")
        raise

if __name__ == "__main__":
    main()
