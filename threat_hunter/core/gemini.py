
import google.generativeai as genai
from threat_hunter.utils.logger import logger

class Gemini:
    def __init__(self, api_keys):
        self.api_keys = api_keys
        self.current_api_key_index = 0
        self.configure_api_key()

    def configure_api_key(self):
        genai.configure(api_key=self.api_keys[self.current_api_key_index])

    def switch_api_key(self):
        self.current_api_key_index = (self.current_api_key_index + 1) % len(self.api_keys)
        self.configure_api_key()
        logger.info(f"Switched to API key index {self.current_api_key_index}")

    def generate_content(self, prompt):
        try:
            model = genai.GenerativeModel('gemini-pro')
            response = model.generate_content(prompt)
            return response.text
        except Exception as e:
            logger.error(f"Error generating content with Gemini: {e}")
            self.switch_api_key()
            model = genai.GenerativeModel('gemini-pro')
            response = model.generate_content(prompt)
            return response.text
