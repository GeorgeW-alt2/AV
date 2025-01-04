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
import json

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
                if 32 <= byte <= 126:  # Printable ASCII characters
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
        
        # Fix the length mismatch - make sure labels match the number of sequences
        labels = np.repeat(labels, len(sequences) // len(labels))
        
        # Ensure lengths match
        min_len = min(len(padded_sequences), len(labels))
        padded_sequences = padded_sequences[:min_len]
        labels = labels[:min_len]
        
        logging.info(f"Prepared {len(padded_sequences)} sequences with matching labels")
        return padded_sequences, np.array(labels), self.tokenizer

    def save_model(self, model: nn.Module, path: str, optimizer: optim.Optimizer, epoch: int):
        """Save model checkpoint."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        torch.save({
            'epoch': epoch,
            'model_state_dict': model.state_dict(),
            'optimizer_state_dict': optimizer.state_dict(),
            'tokenizer': self.tokenizer,
            'max_len': self.max_len
        }, path)
        logging.info(f"Model saved to {path}")

    def save_tokenizer(self, path: str):
        """Save tokenizer to JSON file."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            json.dump(self.tokenizer, f)
        logging.info(f"Tokenizer saved to {path}")

    def load_model(self, model: nn.Module, path: str, optimizer: optim.Optimizer = None) -> Tuple[nn.Module, optim.Optimizer, int]:
        """Load model checkpoint."""
        checkpoint = torch.load(path)
        model.load_state_dict(checkpoint['model_state_dict'])
        if optimizer:
            optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
        self.tokenizer = checkpoint['tokenizer']
        self.max_len = checkpoint['max_len']
        return model, optimizer, checkpoint['epoch']

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
        self.lstm1 = nn.LSTM(
            embedding_dim, 
            embedding_dim, 
            num_layers=2,
            batch_first=True, 
            dropout=0.5
        )
        self.lstm2 = nn.LSTM(
            embedding_dim, 
            64, 
            num_layers=2,
            batch_first=True, 
            dropout=0.5
        )
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
    Load executable paths from two separate files and assign labels.
    
    Args:
        clean_file_path (str): Path to clean executables list
        dirty_file_path (str): Path to malicious executables list
        
    Returns:
        Tuple of (exe_paths, labels)
    """
    try:
        with open(clean_file_path, 'r') as clean_file:
            clean_paths = [line.strip() for line in clean_file.readlines()]
        
        with open(dirty_file_path, 'r') as dirty_file:
            dirty_paths = [line.strip() for line in dirty_file.readlines()]
        
        labels = [0] * len(clean_paths) + [1] * len(dirty_paths)
        exe_paths = clean_paths + dirty_paths
        
        logging.info(f"Loaded {len(exe_paths)} executable paths with labels")
        return exe_paths, labels
    
    except Exception as e:
        logging.error(f"Error loading executable paths and labels: {e}")
        raise

def main():
    # Configuration settings
    clean_file_path = 'clean.txt'
    dirty_file_path = 'dirty.txt'
    max_len = 100
    min_string_length = 4
    batch_size = 32
    num_epochs = 10
    learning_rate = 0.001
    model_save_path = 'models/exe_scanner_model.pth'
    tokenizer_save_path = 'models/tokenizer.json'

    # Initialize scanner
    scanner = ExeScanner(max_len=max_len, min_string_length=min_string_length)
    
    try:
        # Load executable paths and labels
        exe_paths, labels = load_exe_paths_and_labels(clean_file_path, dirty_file_path)
        
        # Extract strings from executables
        all_strings = []
        all_labels = []
        for path, label in zip(exe_paths, labels):
            try:
                strings = scanner.extract_strings_from_exe(path)
                all_strings.extend(strings)
                all_labels.extend([label] * len(strings))
            except Exception as e:
                logging.warning(f"Skipping file {path}: {e}")
                continue
        
        # Prepare data
        X, y, tokenizer = scanner.prepare_data(all_strings, all_labels)
        
        # Create dataset and dataloader
        dataset = ExeDataset(X, y)
        train_loader = DataLoader(
            dataset, 
            batch_size=min(batch_size, len(dataset)),
            shuffle=True
        )
        
        # Initialize model and move to device
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model = ExeScannerModel(vocab_size=len(tokenizer), input_length=max_len)
        model = model.to(device)
        
        # Set up loss function and optimizer
        criterion = nn.CrossEntropyLoss()
        optimizer = optim.Adam(model.parameters(), lr=learning_rate)
        
        # Load existing model if available
        start_epoch = 0
        if os.path.exists(model_save_path):
            try:
                model, optimizer, start_epoch = scanner.load_model(model, model_save_path, optimizer)
                logging.info(f"Resumed training from epoch {start_epoch}")
            except Exception as e:
                logging.warning(f"Could not load existing model, starting fresh: {e}")
        
        # Train model
        for epoch in range(start_epoch, num_epochs):
            train_model(model, train_loader, criterion, optimizer, device, num_epochs=1)
            
            # Save checkpoints
            try:
                scanner.save_model(model, model_save_path, optimizer, epoch + 1)
                scanner.save_tokenizer(tokenizer_save_path)
            except Exception as e:
                logging.error(f"Failed to save checkpoint: {e}")
        
        # Test prediction
        test_file = "test.exe"
        if os.path.exists(test_file):
            try:
                model.eval()
                test_strings = scanner.extract_strings_from_exe(test_file)
                test_sequences, _, _ = scanner.prepare_data(test_strings, [0] * len(test_strings))
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
