import joblib
import os

def load_model(model_name):  # Load models without extensions
    """
    Load a machine learning model from the dumped_models directory.
    
    :param model_name: The name of the model file (without extension).
    :return: The loaded model.
    """
    model_name = f"dumped.{model_name}"  # Update to include 'dumped.' prefix
    possible_extensions = ['.joblib', '']  # Check for .joblib and no extension
    for ext in possible_extensions:
        model_path = os.path.join(os.path.dirname(__file__), f"{model_name}{ext}")
        if os.path.exists(model_path):
            return joblib.load(model_path)
    raise FileNotFoundError(f"Model {model_name} not found in dumped_models.")

def load_joblib(model_name):  # Load models with .joblib extension
    """
    Load a joblib model from the dumped_models directory.
    
    :param model_name: The name of the joblib model file (without extension).
    :return: The loaded model.
    """
    model_path = os.path.join(os.path.dirname(__file__), f"{model_name}.joblib")
    if os.path.exists(model_path):
        return joblib.load(model_path)
    raise FileNotFoundError(f"Joblib model {model_name} not found in dumped_models.")
