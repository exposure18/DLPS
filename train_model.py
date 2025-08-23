import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import os

# --- Load the Prepared Data ---
print("Loading data...")
try:
    X_train = np.load('X_train.npy')
    X_test = np.load('X_test.npy')
    y_train = np.load('y_train.npy')
    y_test = np.load('y_test.npy')
    print("Data loaded successfully.")
    print(f"X_train shape: {X_train.shape}")
    print(f"y_train shape: {y_train.shape}")
    print(f"X_test shape: {X_test.shape}")
    print(f"y_test shape: {y_test.shape}")

except FileNotFoundError:
    print("Error: .npy files not found. Please ensure 'prepare_data.py' was run successfully.")
    exit()
except Exception as e:
    print(f"An error occurred while loading data: {e}")
    exit()

# Determine the number of features (input dimension for the model)
num_features = X_train.shape[1]
print(f"Number of features: {num_features}")

# --- Build the Deep Learning Model ---
print("\nBuilding the Deep Learning Model...")
model = Sequential([
    # Input layer: Dense layer with 'relu' activation, matching input features
    Dense(128, activation='relu', input_shape=(num_features,)),
    Dropout(0.3), # Dropout for regularization, helps prevent overfitting

    # Hidden layer 1
    Dense(64, activation='relu'),
    Dropout(0.3),

    # Hidden layer 2
    Dense(32, activation='relu'),
    Dropout(0.3),

    # Output layer: Single neuron for binary classification ('sigmoid' activation)
    # Sigmoid outputs a probability between 0 and 1
    Dense(1, activation='sigmoid')
])

# --- Compile the Model ---
# Optimizer: Adam is a good general-purpose optimizer
# Loss function: binary_crossentropy for binary classification
# Metrics: accuracy to monitor performance
model.compile(optimizer=Adam(learning_rate=0.001),
              loss='binary_crossentropy',
              metrics=['accuracy'])

model.summary() # Print a summary of the model architecture

# --- Define Callbacks for Training ---
# EarlyStopping: Stop training if validation accuracy doesn't improve for 'patience' epochs
early_stopping = EarlyStopping(monitor='val_accuracy', patience=10, restore_best_weights=True)

# ModelCheckpoint: Save the best model during training based on validation accuracy
model_checkpoint = ModelCheckpoint('network_ids_model.h5', monitor='val_accuracy', save_best_only=True, verbose=1)

# --- Train the Model ---
print("\nTraining the model...")
history = model.fit(
    X_train, y_train,
    epochs=100, # Max epochs, but EarlyStopping will likely stop it sooner
    batch_size=32,
    validation_split=0.1, # Use 10% of training data for validation during training
    callbacks=[early_stopping, model_checkpoint],
    verbose=1 # Show training progress
)
print("Model training complete.")

# --- Evaluate the Model on Test Data ---
print("\nEvaluating the model on test data...")
loss, accuracy = model.evaluate(X_test, y_test, verbose=0)
print(f"Test Loss: {loss:.4f}")
print(f"Test Accuracy: {accuracy:.4f}")

# --- Make Predictions and Show Classification Report ---
print("\nGenerating classification report...")
y_pred_prob = model.predict(X_test)
y_pred = (y_pred_prob > 0.5).astype(int) # Convert probabilities to binary predictions (0 or 1)

print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['Normal (0)', 'Attack (1)']))

print("\nConfusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print(cm)

# Calculate individual metrics from confusion matrix for clarity
tn, fp, fn, tp = cm.ravel()
print(f"\nTrue Negatives (Correctly identified Normal): {tn}")
print(f"False Positives (Normal identified as Attack): {fp}")
print(f"False Negatives (Attack identified as Normal): {fn}")
print(f"True Positives (Correctly identified Attack): {tp}")

# --- Save the Final Trained Model (if not already saved by checkpoint) ---
# The ModelCheckpoint already saves the best model during training.
# This block is just for confirmation or if you want to save the final epoch's model
# regardless of validation performance (though `save_best_only=True` makes that redundant).
# For now, rely on ModelCheckpoint.
print("\nBest model saved as 'network_ids_model.h5' by ModelCheckpoint during training.")