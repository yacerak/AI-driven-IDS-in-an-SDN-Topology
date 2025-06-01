

# SDN Intrusion Detection System using Ryu and Machine Learning

## Overview

This project implements a flexible and extensible Intrusion Detection System (IDS) built upon the Software-Defined Networking (SDN) paradigm using the Ryu OpenFlow controller framework. It leverages various machine learning models to analyze network traffic in real-time, identify potential threats based on the NSL-KDD feature set, and proactively block malicious traffic flows within the network. The system is designed to work with OpenFlow-enabled switches and includes components for traffic simulation, feature extraction, and multiple ML-based detection engines.

## Features

*   **SDN-based Control**: Utilizes the Ryu OpenFlow controller for centralized network visibility and control.
*   **Multiple ML Models**: Offers implementations for various machine learning classifiers, including K-Nearest Neighbors (Binary and Multi-class), Linear SVM, Quadratic SVM, Multi-Layer Perceptron (MLP), and Long Short-Term Memory (LSTM) networks.
*   **NSL-KDD Feature Extraction**: Employs a dedicated module (`decoder2.py`) to extract the comprehensive NSL-KDD feature set from raw network packets.
*   **Real-time Detection & Response**: Analyzes traffic flows and makes predictions in near real-time, installing flow rules on SDN switches to block identified threats.
*   **Traffic Simulation**: Includes a script (`dataflow2.py`) using Scapy to generate realistic network traffic flows based on the NSL-KDD dataset for testing and evaluation purposes.
*   **Modular Design**: The components (controller applications, decoder, simulator) are designed modularly, allowing for easier extension and modification.
*   **Basic L2 Switching**: Integrates standard learning switch functionality alongside IDS capabilities.

## Architecture

The system follows a typical SDN architecture enhanced with ML-driven security:

1.  **Data Plane**: Consists of OpenFlow-enabled switches forwarding network traffic.
2.  **Control Plane**: The Ryu controller runs as the central brain. One of the provided `*IDS.py` applications is loaded into Ryu.
3.  **Application Plane**: The loaded IDS application performs the following:
    *   Receives packets forwarded by the switches (Packet-In messages).
    *   Utilizes the `NSLKDDDecoder` module (`decoder2.py`) to parse packets and extract NSL-KDD features.
    *   Preprocesses the extracted features (e.g., one-hot encoding categorical features using a pre-trained encoder).
    *   Feeds the processed features into a pre-trained machine learning model (loaded from the `modeles/` directory).
    *   Based on the model's prediction (e.g., 'normal', 'abnormal', or specific attack types like 'DoS', 'probe'), it decides on an action.
    *   If an attack is detected, it instructs the switch (via Flow-Mod messages) to install rules blocking traffic from the offending source IP address.
    *   For normal traffic, it performs standard L2 MAC address learning and installs forwarding rules.

## Components

*   **Ryu Controller Applications (`*IDS.py`)**: These are the core IDS applications run by Ryu. Each script implements the control logic and integrates a specific ML model:
    *   `binKnnIDS.py`: Binary K-Nearest Neighbors.
    *   `lsvmIDS.py`: Linear Support Vector Machine.
    *   `QsvmIDS.py`: Quadratic Support Vector Machine.
    *   `mKnnIDS.py`: Multi-class K-Nearest Neighbors.
    *   `MlpIDS.py`: Multi-Layer Perceptron (using Keras/TensorFlow).
    *   `LstmIDS.py`: Long Short-Term Memory network (using ONNX Runtime for inference).
*   **Feature Extractor (`decoder2.py`)**: Contains the `NSLKDDDecoder` class responsible for processing raw packet data and generating the 41 NSL-KDD features.
*   **Traffic Simulator (`dataflow2.py`)**: A standalone Scapy-based script to generate network traffic mimicking patterns from the NSL-KDD dataset (`KDDTest-21.txt`). It simulates TCP, UDP, and ICMP flows and logs the ground truth labels for evaluation.
*   **Simple Switch (`switch13.py`)**: A basic Ryu application demonstrating L2 learning switch functionality using OpenFlow 1.3.
*   **Models (`modeles/` directory - *assumed*)**: This directory should contain the pre-trained machine learning models and associated preprocessing objects (encoders, binarizers) required by the IDS applications. Example files mentioned in the code include:
    *   `onehot_encoder.pkl`
    *   `label_binarizer.pkl`
    *   `binaryKNN.pkl`
    *   `LinearSVM.pkl`
    *   `QuadraticSVM.pkl`
    *   `MultiKnn.pkl`
    *   `MLP.h5`
    *   `lstm_quant.onnx`

## Requirements

*   Python 3.x
*   Ryu SDN Framework
*   Scapy
*   Pandas
*   NumPy
*   Joblib
*   Scikit-learn (implied by joblib usage and model types)
*   TensorFlow / Keras (for `MlpIDS.py`)
*   ONNX Runtime (for `LstmIDS.py`)
*   An OpenFlow 1.3 compatible switch (e.g., Open vSwitch) or simulator (e.g., Mininet).
*   NSL-KDD Dataset files (specifically `KDDTest-21.txt` for the simulator).

## Installation

1.  **Clone the repository (or place the scripts in a directory):**
    ```bash
    # git clone <repository_url> # If applicable
    # cd <repository_directory>
    ```
2.  **Install Python dependencies:**
    ```bash
    pip install ryu pandas numpy joblib scapy scikit-learn tensorflow onnxruntime
    ```
    *Note: Ensure you have the necessary system libraries for these Python packages.*
3.  **Set up the `modeles/` directory:** Create a directory named `modeles` in the same location as the Python scripts and place all the required pre-trained model files (`.pkl`, `.h5`, `.onnx`) and the encoder/binarizer files inside it.
4.  **Obtain NSL-KDD Data:** Download the `KDDTest-21.txt` file (or the relevant dataset file used for training/simulation) and place it where `dataflow2.py` can access it (e.g., the project root directory).
5.  **Set up an SDN environment:** Install and configure Mininet or connect physical/virtual OpenFlow switches.

## Usage

1.  **Start the Ryu Controller with an IDS Application:**
    Choose one of the IDS controller scripts (e.g., `MlpIDS.py`) and run it using Ryu Manager:
    ```bash
    ryu-manager MlpIDS.py
    ```
    *Ryu will start and wait for switches to connect.*

2.  **Connect Switches:** Start your Mininet topology or connect your OpenFlow switches to the Ryu controller's IP address and default port (usually 6633 or 6653).

3.  **Generate Traffic (Optional but Recommended for Testing):**
    Run the traffic simulator script in a separate terminal. This requires root privileges for raw socket access used by Scapy:
    ```bash
    sudo python3 dataflow2.py
    ```
    *This script will start sending simulated traffic based on the KDDTest-21 dataset onto the network. It will also create a `true_labels.csv` file logging the ground truth for the generated flows.*

4.  **Monitor:** Observe the Ryu controller logs. The IDS application will log information about processed packets, detected threats, and blocking actions. Specific applications might create prediction log files (e.g., `predictions_ltsm.csv` for `LstmIDS.py`).

## Models

The system relies on pre-trained machine learning models stored in the `modeles/` directory. Each `*IDS.py` script loads a specific model:

*   **`binaryKNN.pkl`**: Used by `binKnnIDS.py` for binary (normal/abnormal) classification.
*   **`LinearSVM.pkl`**: Used by `lsvmIDS.py` for binary classification.
*   **`QuadraticSVM.pkl`**: Used by `QsvmIDS.py` for binary classification.
*   **`MultiKnn.pkl`**: Used by `mKnnIDS.py` for multi-class attack classification.
*   **`MLP.h5`**: A Keras/TensorFlow model used by `MlpIDS.py` (likely for multi-class classification).
*   **`lstm_quant.onnx`**: A quantized LSTM model in ONNX format used by `LstmIDS.py` (likely for binary or multi-class classification).

Additionally, preprocessing objects are required:

*   **`onehot_encoder.pkl`**: A Scikit-learn OneHotEncoder fitted on the categorical features (`protocol_type`, `service`, `flag`) of the training data.
*   **`label_binarizer.pkl`**: A Scikit-learn LabelBinarizer used by multi-class models (`mKnnIDS.py`, `MlpIDS.py`) to handle attack labels.

*Ensure these model and preprocessing files are correctly trained and placed in the `modeles/` directory before running the corresponding IDS applications.*

