
import logging

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('threat_hunter.log')
        ]
    )
    return logging.getLogger(__name__)

logger = setup_logging()
