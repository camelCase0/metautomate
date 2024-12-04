import os
import shutil

class ScriptManager:
    """
    Manages the uploading, validation, and storage of custom Nmap scripts.
    """
    SCRIPT_DIRECTORY = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "custom_scripts"))  # Directory to store custom scripts

    def __init__(self):
        # Ensure the script directory exists
        os.makedirs(self.SCRIPT_DIRECTORY, exist_ok=True)

    def upload_script(self, script_path, new_script_name=None):
        """
        Uploads a custom Nmap script to the designated directory.

        Parameters:
        - script_path (str): Path to the script file to upload.
        - new_script_name (str): Optional new name for the uploaded script.

        Returns:
        - str: Path to the uploaded script in the `custom_scripts` directory.
        """
        if not script_path.endswith(".nse"):
            raise ValueError("Only Nmap scripts (*.nse) are allowed.")

        # Determine the destination path
        script_name = new_script_name or os.path.basename(script_path)
        destination_path = os.path.join(self.SCRIPT_DIRECTORY, script_name)

        # Copy the script to the custom scripts directory
        shutil.copy2(script_path, destination_path)
        return destination_path

    def list_scripts(self):
        """
        Lists all custom scripts in the designated directory.

        Returns:
        - list: List of filenames of available custom scripts.
        """
        return [
            script for script in os.listdir(self.SCRIPT_DIRECTORY)
            if script.endswith(".nse")
        ]

    def delete_script(self, script_name):
        """
        Deletes a custom script from the directory.

        Parameters:
        - script_name (str): Name of the script to delete.

        Returns:
        - bool: True if the script was successfully deleted, False otherwise.
        """
        script_path = os.path.join(self.SCRIPT_DIRECTORY, script_name)
        if os.path.exists(script_path):
            os.remove(script_path)
            return True
        return False

    def validate_script(self, script_path):
        """
        Validates the syntax and basic structure of an Nmap script.

        Parameters:
        - script_path (str): Path to the script file.

        Returns:
        - bool: True if the script passes validation, False otherwise.
        """
        try:
            with open(script_path, "r") as script_file:
                content = script_file.read()
                # Basic validation: Check for mandatory "description" field
                if "description" not in content:
                    raise ValueError("Script lacks a 'description' field.")
            return True
        except Exception as e:
            raise ValueError(f"Script validation failed: {e}")