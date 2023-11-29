def unzip_file(artifact_id=None, container_id=None, default_tag=None, default_severity=None, default_label=None, pwd=None, **kwargs):
    """
    This Python script unpacks ZIP and RAR files that can be protected by an optional password. It handles a list of file paths with corresponding passwords, adds a prefix-based renaming scheme to the unzipped files and calculates their SHA256 and MD5 hash values. The results are saved in a JSON format containing the path, file name, name of the original archive and the calculated hash values. The script also supports unpacking files without a password.
    
    Args:
        artifact_id: A list of Artifat IDs. These artifacts must contain the following information: VaultID. Optionally a password.
        container_id
        default_tag
        default_severity
        default_label
        pwd
    
    Returns a JSON-serializable object that implements the configured data paths:
        
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import hashlib
    import zipfile
    import datetime
    from phantom.vault import Vault
    import os
    import shutil
        
    
    outputs = {}
    
    # Write your custom code here...
    default_tag = default_tag
    extract_to = Vault.get_vault_tmp_dir() + '/'
    def process_value(value):
        """Prozessiert den Wert, indem `.lower()` auf Strings angewendet wird."""
        if isinstance(value, str):
            return value.lower()
        elif isinstance(value, list):
            return [process_value(item) for item in value]
        else:
            return value

    def adjust_dictionary(d):
        """Passt alle Werte in einem verschachtelten Dictionary an."""
        for key, value in d.items():
            if isinstance(value, dict):
                adjust_dictionary(value)
            else:
                d[key] = process_value(value)
                
    def stringify_values(d):
        """Convert all values in a nested dictionary to strings, handling lists appropriately."""
        for key, value in d.items():
            if isinstance(value, dict):
                stringify_values(value)
            elif isinstance(value, list):
                d[key] = [str(item) if not isinstance(item, str) else item for item in value]
            else:
                d[key] = str(value)


    def http_post(data,url_param,url_param_2=None):
            phantom.debug(f"HTTP POST Param: {url_param_2}")
            url = phantom.build_phantom_rest_url(url_param)
            if url_param_2 is not None:
                url = url +'/'+url_param_2
            else:
                phantom.debug("no second param")

            phantom.debug(f"HTTP POST URL: {url}")
            try:
                response = phantom.requests.post(url, data=data, headers={'Content-Type': 'application/json'}, verify=False)
                response_data = response.json()
                phantom.debug(f"HTTP POST request: {response_data}")
            except ValueError:
                # Fängt Fehler, wenn die Antwort keinen gültigen JSON-Inhalt hat
                phantom.debug("Invalid JSON response")
                response_data = response.text
            return response_data
                
    def calculate_hashes(file_path):
        """Calculate MD5 and SHA256 hashes of a file."""
        sha256_hash = hashlib.sha256()
        md5_hash = hashlib.md5()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
                md5_hash.update(byte_block)
        return sha256_hash.hexdigest(), md5_hash.hexdigest()

    def add_prefix_and_extract(zip_ref, extract_to, prefix, parent_archive_name,default_tag,default_severity,default_label,container_id, password=None):
        """Extract files from zip, add a prefix, calculate hashes, and add to results."""
        phantom.debug(f"password: {password}")
        # Create a unique subfolder for extracted files
        unique_subfolder = f"{extract_to}{prefix}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}/"
        os.makedirs(unique_subfolder, exist_ok=True)
        if password:
            zip_ref.setpassword(password.encode())
            
        # Process each file in the archive
        for member in zip_ref.namelist():
            if member.endswith('/'):
                os.makedirs(os.path.join(unique_subfolder, member), exist_ok=True)
            else:
                try:
                    extracted_path = zip_ref.extract(member, unique_subfolder)
                    file_name = prefix + '_' + os.path.basename(member)
                    sub_dir = os.path.dirname(member)
                    new_path = os.path.join(unique_subfolder, sub_dir, file_name)
                    os.makedirs(os.path.dirname(new_path), exist_ok=True)  # Create any necessary subdirectories
                    os.rename(extracted_path, new_path)
                    sha256, md5 = calculate_hashes(new_path)
                    
                    # Add file to vault and append info to results
                    success, message, vault_id = phantom.vault_add(container=container_id, file_location=new_path, file_name=file_name, metadata=None, trace=False)
                    
                    name = 'Vault Artifact: ' + member
                    
                    # Überprüfen Sie, ob default_tag bereits eine Liste ist. Wenn nicht, machen Sie es zu einer Liste.
                    if not isinstance(default_tag, list):
                        efault_tag = [default_tag] if default_tag else []

                        
                    a_json = {
                        "cef": {
                        "filename": member,
                        "parent_archive_name": parent_archive_name,
                        "sha256": sha256,
                        "md5": md5,
                        "vaultId": vault_id
                        },
                        "container_id": container_id,
                        "severity": default_severity,
                        "label": default_label,
                        "name": name,
                        "tags": default_tag
                    }
                    #stringify_values(a_json)
                    a_json = json.dumps(a_json)
                    phantom.debug(a_json)
                    http_post(a_json,'artifact')
                except RuntimeError as e:
                    if 'encrypted' in str(e):
                        phantom.debug(f"Cannot extract {member}: File is encrypted and requires a password.")
                        continue
                    else:
                        raise
            
        # Clean up by removing the subfolder
        shutil.rmtree(unique_subfolder)
                
    def http_get(url_param,url_param2=None,url_filter=None):
        """Make a GET request to a specified URL."""
        url = phantom.build_phantom_rest_url(url_param,url_param2)
        if url_filter is not None:
            url = url + url_filter
        response = phantom.requests.get(url, verify=False)
        return response.json()

    # Process each artifact
    for item in artifact_id:
        data = http_get('artifact', item)
        vault_id = data["cef"]["vaultId"]
        success, message, info = phantom.vault_info(vault_id=vault_id, container_id=container_id)
        file_name = info[0]['name']
        file_path = info[0]['path']
        
        parent_archive_name = file_name
        file_extension = parent_archive_name.split('.')[-1].lower()  # Extracting file extension
        try:
            prefix = parent_archive_name.split('.')[0]  # Prefix based on file name
            pwd = pwd.encode()  # Example password
            

            # Process ZIP files
            if file_extension == 'zip':
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    if pwd or zip_ref.getinfo(zip_ref.namelist()[0]).flag_bits & 0x1:
                        zip_ref.extractall(pwd=pwd)
                    else:
                        zip_ref.extractall()
                    add_prefix_and_extract(zip_ref, extract_to, prefix, parent_archive_name,default_tag,default_severity,default_label,container_id,pwd)
            else:
                phantom.debug(f"File format of {parent_archive_name} is not supported.")

        except zipfile.BadZipFile as e:
            phantom.debug(f"Error with ZIP file {parent_archive_name}: {e}")
        except Exception as e:
            phantom.debug(f"General error {parent_archive_name}: {e}")

    # Output the results in JSON format
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
