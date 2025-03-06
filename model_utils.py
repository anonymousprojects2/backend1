import os
import torch
from transformers import BertTokenizer, BertForSequenceClassification, BertConfig
from safetensors.torch import load_file

class BERTPredictor:
    def __init__(self):
        self.model_dir = os.path.join(os.path.dirname(__file__), 'trained_model')
        self.vocab_path = os.path.join(self.model_dir, 'vocab.txt')
        self.tokenizer_config_path = os.path.join(self.model_dir, 'tokenizer_config.json')
        self.safetensors_path = os.path.join(self.model_dir, 'model.safetensors')
        self.config_path = os.path.join(self.model_dir, 'config.json')
        
        # Initialize tokenizer and model
        self.tokenizer = self._load_tokenizer()
        self.model = self._load_model()
        self.model.eval()

    def _load_tokenizer(self):
        return BertTokenizer(
            vocab_file=self.vocab_path,
            do_lower_case=True,
            model_max_length=512,
            tokenizer_config_file=self.tokenizer_config_path
        )

    def _load_model(self):
        if not os.path.exists(self.config_path):
            config = BertConfig.from_pretrained('bert-base-uncased', num_labels=2)
        else:
            config = BertConfig.from_pretrained(self.config_path)
        
        model = BertForSequenceClassification(config)
        state_dict = load_file(self.safetensors_path)
        model.load_state_dict(state_dict)
        return model

    def predict(self, text):
        """
        Analyze text for vulnerabilities
        Returns: dict with prediction and confidence
        """
        inputs = self.tokenizer(text, return_tensors='pt', max_length=512, truncation=True, padding=True)
        with torch.no_grad():
            outputs = self.model(**inputs)
            prediction = torch.softmax(outputs.logits, dim=1).tolist()[0]
            
        return {
            'vulnerability': 'Detected' if prediction[1] > 0.5 else 'Safe',
            'confidence': float(max(prediction)),
            'raw_scores': [float(x) for x in prediction]
        }

    def batch_predict(self, texts):
        """
        Analyze multiple texts for vulnerabilities
        Returns: list of prediction dicts
        """
        inputs = self.tokenizer(texts, return_tensors='pt', max_length=512, truncation=True, padding=True)
        with torch.no_grad():
            outputs = self.model(**inputs)
            predictions = torch.softmax(outputs.logits, dim=1).tolist()
            
        return [{
            'vulnerability': 'Detected' if pred[1] > 0.5 else 'Safe',
            'confidence': float(max(pred)),
            'raw_scores': [float(x) for x in pred]
        } for pred in predictions] 