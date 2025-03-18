@app.route('/retrieve', methods=['POST'])
def retrieve():
    data = request.json
    token = data.get("token")

    if not token:
        logging.warning("❌ No token provided.")
        return jsonify({"error": "❌ Token is required."}), 400

    # ✅ Load stored token from file
    id_number = verify_token(token)
    stored_token = load_token_from_file(id_number)

    if stored_token != token:
        logging.warning(f"❌ Unauthorized access attempt with invalid token.")
        return jsonify({"error": "❌ Invalid or Expired Token"}), 401

    if id_number not in AES_KEY_STORAGE:
        logging.warning(f"❌ AES Key missing for ID: {id_number}.")
        return jsonify({"error": "❌ AES Key not found for this ID"}), 400

    cid = FILECOIN_CID
    if not cid:
        logging.warning(f"❌ CID not found for ID: {id_number}.")
        return jsonify({"error": "❌ No CID found in environment variables."}), 400

    try:
        # ✅ Correct Filecoin retrieval
        response = storage.get_file(cid)  

        if response.status_code != 200:
            logging.warning(f"❌ Unable to fetch file from Filecoin for ID: {id_number}.")
            return jsonify({"error": "❌ Unable to fetch file from Filecoin"}), 500

        encrypted_data = response.content  # Get the binary content of the file

        # Decrypt data
        aes_key = AES_KEY_STORAGE.get(id_number, ENCRYPTED_AES_KEY)
        iv = encrypted_data[:16]  
        ciphertext = encrypted_data[16:]  

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        logging.info(f"✅ Retrieval successful for ID: {id_number}.")

        return jsonify({"filecoin_cid": cid, "decrypted_id": decrypted_data.strip().decode()}), 200
    except Exception as e:
        logging.error(f"❌ Retrieval failed for ID: {id_number}. Error: {str(e)}")
        return jsonify({"error": f"❌ Retrieval failed: {str(e)}"}), 500
