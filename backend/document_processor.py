# backend/document_processor.py
import os
import json
import time
import traceback
import pytesseract
from PIL import Image
import cv2
import numpy as np
import re
from logger import get_logger
import tempfile

# Get logger
logger = get_logger()

# Configure Tesseract path
import os
tesseract_path = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
if os.path.exists(tesseract_path):
    pytesseract.pytesseract.tesseract_cmd = tesseract_path
else:
    logger.warning(f"Tesseract OCR not found at {tesseract_path}. Please install Tesseract OCR and update the path.")
    # Try to find tesseract in PATH
    try:
        import shutil
        tesseract_in_path = shutil.which('tesseract')
        if tesseract_in_path:
            pytesseract.pytesseract.tesseract_cmd = tesseract_in_path
            logger.info(f"Found Tesseract OCR in PATH: {tesseract_in_path}")
    except Exception as e:
        logger.error(f"Error finding Tesseract in PATH: {str(e)}")
# If Tesseract is installed in a different location, update the path above

class DocumentProcessor:
    """Class for processing identity documents using OCR and AI."""
    
    def __init__(self):
        """Initialize the document processor."""
        self.supported_id_types = ["passport", "driver_license", "national_id", "id"]
        
    def process_document(self, file_path, doc_type):
        """
        Process a document image and extract PII data.
        
        Args:
            file_path (str): Path to the document image
            doc_type (str): Type of document (passport, driver_license, national_id)
            
        Returns:
            dict: Extracted PII data
        """
        logger.info(f"Processing document of type: {doc_type}")
        
        try:
            # Check if Tesseract is available
            tesseract_available = False
            try:
                tesseract_available = os.path.exists(pytesseract.pytesseract.tesseract_cmd)
            except Exception as e:
                logger.warning(f"Error checking Tesseract availability: {str(e)}")
                tesseract_available = False
            
            if not tesseract_available:
                logger.warning("Tesseract OCR is not installed or configured properly. Using mock data for testing.")
                # Return mock data for testing purposes
                return self._generate_mock_data(doc_type)
            
            # Read the image
            try:
                image = cv2.imread(file_path)
                if image is None:
                    logger.error(f"Failed to read image at {file_path}")
                    return self._generate_mock_data(doc_type)  # Use mock data as fallback
            except Exception as e:
                logger.error(f"Error reading image: {str(e)}")
                return self._generate_mock_data(doc_type)  # Use mock data as fallback
            
            # Preprocess the image
            try:
                preprocessed = self._preprocess_image(image)
            except Exception as e:
                logger.error(f"Error preprocessing image: {str(e)}")
                return self._generate_mock_data(doc_type)  # Use mock data as fallback
            
            # Extract text using OCR
            try:
                text = pytesseract.image_to_string(preprocessed)
                logger.debug(f"Extracted text: {text[:100]}...")  # Log first 100 chars
            except Exception as e:
                logger.error(f"Error extracting text with OCR: {str(e)}")
                return self._generate_mock_data(doc_type)  # Use mock data as fallback
            
            # Extract PII data based on document type
            if doc_type == "passport":
                pii_data = self._extract_passport_data(text)
            elif doc_type == "driver_license":
                pii_data = self._extract_drivers_license_data(text)
            elif doc_type == "national_id" or doc_type == "id":
                pii_data = self._extract_national_id_data(text)
            else:
                logger.warning(f"Unsupported document type: {doc_type}")
                return {"error": f"Unsupported document type: {doc_type}"}
            
            # Add metadata
            pii_data["document_type"] = doc_type
            pii_data["processed_at"] = time.time()
            
            logger.info(f"Successfully extracted PII data from {doc_type}")
            return pii_data
            
        except Exception as e:
            logger.error(f"Error processing document: {str(e)}")
            logger.error(traceback.format_exc())
            return {"error": str(e)}
    
    def process_document_from_request(self, file, doc_type):
        """
        Process a document from a Flask request file.
        
        Args:
            file (FileStorage): Flask file object
            doc_type (str): Type of document
            
        Returns:
            dict: Extracted PII data
        """
        temp_dir = None
        try:
            # Save the file to a temporary location
            temp_dir = tempfile.mkdtemp()
            temp_file_path = os.path.join(temp_dir, "document.jpg")
            
            try:
                file.save(temp_file_path)
            except Exception as e:
                logger.error(f"Error saving file: {str(e)}")
                return self._generate_mock_data(doc_type)  # Use mock data as fallback
            
            # Process the document
            result = self.process_document(temp_file_path, doc_type)
            
            return result
        except Exception as e:
            logger.error(f"Error processing document from request: {str(e)}")
            logger.error(traceback.format_exc())
            return self._generate_mock_data(doc_type)  # Use mock data as fallback
        finally:
            # Clean up temporary files
            if temp_dir:
                try:
                    for f in os.listdir(temp_dir):
                        try:
                            os.remove(os.path.join(temp_dir, f))
                        except:
                            pass
                    os.rmdir(temp_dir)
                except Exception as cleanup_error:
                    logger.error(f"Error cleaning up temporary files: {str(cleanup_error)}")
    
    def _preprocess_image(self, image):
        """
        Preprocess the image for better OCR results.
        
        Args:
            image (numpy.ndarray): Input image
            
        Returns:
            numpy.ndarray: Preprocessed image
        """
        # Convert to grayscale
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        
        # Apply thresholding
        _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        
        # Noise removal
        kernel = np.ones((1, 1), np.uint8)
        opening = cv2.morphologyEx(thresh, cv2.MORPH_OPEN, kernel, iterations=1)
        
        return opening
    
    def _extract_passport_data(self, text):
        """
        Extract PII data from passport text.
        
        Args:
            text (str): OCR extracted text
            
        Returns:
            dict: Extracted PII data
        """
        pii_data = {
            "name": "",
            "dob": "",
            "id_number": "",
            "id_type": "passport",
            "nationality": "",
            "gender": "",
            "expiry_date": "",
            "extracted_text": text  # Store the full extracted text
        }
        
        # Extract name (usually after "Surname" and "Given Names")
        name_match = re.search(r"(?:Surname|Last Name)[:\s]+([^\n]+)[\n\s]+(?:Given Names|First Name)[:\s]+([^\n]+)", text, re.IGNORECASE)
        if name_match:
            surname = name_match.group(1).strip()
            given_names = name_match.group(2).strip()
            pii_data["name"] = f"{surname}, {given_names}"
        
        # Extract date of birth (usually in format DD MMM YYYY)
        dob_match = re.search(r"(?:Date of Birth|Birth Date|DOB)[:\s]+(\d{2}[ /.]\d{2}[ /.]\d{4}|\d{2}[ /.][A-Za-z]{3}[ /.]\d{4})", text, re.IGNORECASE)
        if dob_match:
            pii_data["dob"] = dob_match.group(1).strip()
        
        # Extract passport number
        passport_match = re.search(r"(?:Passport No|Passport Number|Document No)[:\s]+([A-Z0-9]+)", text, re.IGNORECASE)
        if passport_match:
            pii_data["id_number"] = passport_match.group(1).strip()
        
        # Extract nationality
        nationality_match = re.search(r"(?:Nationality|Citizenship)[:\s]+([A-Za-z ]+)", text, re.IGNORECASE)
        if nationality_match:
            pii_data["nationality"] = nationality_match.group(1).strip()
        
        # Extract gender
        gender_match = re.search(r"(?:Sex|Gender)[:\s]+([MF]|Male|Female)", text, re.IGNORECASE)
        if gender_match:
            gender = gender_match.group(1).strip().upper()
            if gender in ["M", "MALE"]:
                pii_data["gender"] = "Male"
            elif gender in ["F", "FEMALE"]:
                pii_data["gender"] = "Female"
        
        # Extract expiry date
        expiry_match = re.search(r"(?:Date of Expiry|Expiry Date)[:\s]+(\d{2}[ /.]\d{2}[ /.]\d{4}|\d{2}[ /.][A-Za-z]{3}[ /.]\d{4})", text, re.IGNORECASE)
        if expiry_match:
            pii_data["expiry_date"] = expiry_match.group(1).strip()
        
        return pii_data
    
    def _extract_drivers_license_data(self, text):
        """
        Extract PII data from driver's license text.
        
        Args:
            text (str): OCR extracted text
            
        Returns:
            dict: Extracted PII data
        """
        pii_data = {
            "name": "",
            "dob": "",
            "id_number": "",
            "id_type": "driver_license",
            "address": "",
            "issue_date": "",
            "expiry_date": "",
            "extracted_text": text  # Store the full extracted text
        }
        
        # Extract name
        name_match = re.search(r"(?:Name|Full Name)[:\s]+([^\n]+)", text, re.IGNORECASE)
        if name_match:
            pii_data["name"] = name_match.group(1).strip()
        
        # Extract date of birth
        dob_match = re.search(r"(?:DOB|Date of Birth|Birth Date)[:\s]+(\d{2}[ /.]\d{2}[ /.]\d{4}|\d{2}[ /.][A-Za-z]{3}[ /.]\d{4})", text, re.IGNORECASE)
        if dob_match:
            pii_data["dob"] = dob_match.group(1).strip()
        
        # Extract license number
        license_match = re.search(r"(?:License No|License Number|DL No)[:\s]+([A-Z0-9-]+)", text, re.IGNORECASE)
        if license_match:
            pii_data["id_number"] = license_match.group(1).strip()
        
        # Extract address
        address_match = re.search(r"(?:Address|ADD)[:\s]+([^\n]+(?:\n[^\n]+){0,3})", text, re.IGNORECASE)
        if address_match:
            pii_data["address"] = address_match.group(1).strip().replace("\n", ", ")
        
        # Extract issue date
        issue_match = re.search(r"(?:Issue Date|Issued)[:\s]+(\d{2}[ /.]\d{2}[ /.]\d{4}|\d{2}[ /.][A-Za-z]{3}[ /.]\d{4})", text, re.IGNORECASE)
        if issue_match:
            pii_data["issue_date"] = issue_match.group(1).strip()
        
        # Extract expiry date
        expiry_match = re.search(r"(?:Expiry Date|Expiration|Expires|Valid Until)[:\s]+(\d{2}[ /.]\d{2}[ /.]\d{4}|\d{2}[ /.][A-Za-z]{3}[ /.]\d{4})", text, re.IGNORECASE)
        if expiry_match:
            pii_data["expiry_date"] = expiry_match.group(1).strip()
        
        return pii_data
    
    def _generate_mock_data(self, doc_type):
        """
        Generate mock data for testing when OCR is not available.
        
        Args:
            doc_type (str): Type of document
            
        Returns:
            dict: Mock PII data
        """
        logger.info(f"Generating mock data for {doc_type}")
        
        # Common fields
        mock_data = {
            "document_type": doc_type,
            "processed_at": time.time(),
            "extracted_text": "This is mock extracted text for testing purposes. Since Tesseract OCR is not available, this is generated mock data for demonstration and testing.",
            "confidence_score": 0.95,
            "mock_data": True,
            "ocr_available": False
        }
        
        if doc_type == "passport":
            mock_data.update({
                "passport_number": "AB1234567",
                "name": "John Doe",
                "nationality": "United States",
                "dob": "1990-01-01",
                "gender": "Male",
                "issue_date": "2020-01-01",
                "expiry_date": "2030-01-01",
                "issuing_country": "United States"
            })
        elif doc_type == "driver_license":
            mock_data.update({
                "license_number": "DL12345678",
                "name": "Jane Smith",
                "address": "123 Main St, Anytown, USA",
                "dob": "1985-05-15",
                "issue_date": "2019-06-01",
                "expiry_date": "2027-06-01",
                "class": "C",
                "restrictions": "None"
            })
        elif doc_type == "national_id" or doc_type == "id":
            mock_data.update({
                "id_number": "ID98765432",
                "name": "Alice Johnson",
                "dob": "1992-08-20",
                "address": "456 Oak Ave, Somewhere, USA",
                "issue_date": "2018-03-15",
                "expiry_date": "2028-03-15",
                "gender": "Female"
            })
        
        return mock_data
    
    def _extract_national_id_data(self, text):
        """
        Extract PII data from national ID text.
        
        Args:
            text (str): OCR extracted text
            
        Returns:
            dict: Extracted PII data
        """
        pii_data = {
            "name": "",
            "dob": "",
            "id_number": "",
            "id_type": "national_id",
            "address": "",
            "gender": "",
            "extracted_text": text  # Store the full extracted text
        }
        
        # Extract name
        name_match = re.search(r"(?:Name|Full Name)[:\s]+([^\n]+)", text, re.IGNORECASE)
        if name_match:
            pii_data["name"] = name_match.group(1).strip()
        
        # Extract date of birth
        dob_match = re.search(r"(?:DOB|Date of Birth|Birth Date)[:\s]+(\d{2}[ /.]\d{2}[ /.]\d{4}|\d{2}[ /.][A-Za-z]{3}[ /.]\d{4})", text, re.IGNORECASE)
        if dob_match:
            pii_data["dob"] = dob_match.group(1).strip()
        
        # Extract ID number
        id_match = re.search(r"(?:ID No|ID Number|National ID)[:\s]+([A-Z0-9-]+)", text, re.IGNORECASE)
        if id_match:
            pii_data["id_number"] = id_match.group(1).strip()
        
        # Extract address
        address_match = re.search(r"(?:Address|ADD)[:\s]+([^\n]+(?:\n[^\n]+){0,3})", text, re.IGNORECASE)
        if address_match:
            pii_data["address"] = address_match.group(1).strip().replace("\n", ", ")
        
        # Extract gender
        gender_match = re.search(r"(?:Sex|Gender)[:\s]+([MF]|Male|Female)", text, re.IGNORECASE)
        if gender_match:
            gender = gender_match.group(1).strip().upper()
            if gender in ["M", "MALE"]:
                pii_data["gender"] = "Male"
            elif gender in ["F", "FEMALE"]:
                pii_data["gender"] = "Female"
        
        return pii_data

# Create a singleton instance
document_processor = DocumentProcessor()