from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.responses import HTMLResponse
import boto3
from botocore.exceptions import ClientError

app = FastAPI()

# AWS S3 Configuration
S3_BUCKET_NAME = "dream-store-bucket"
AWS_REGION = "us-east-1"
s3_client = boto3.client("s3", region_name=AWS_REGION)

# HTML form for user input
html_form = """
<!DOCTYPE html>
<html>
<head>
    <title>Upload File</title>
</head>
<body>
    <form action="/upload" enctype="multipart/form-data" method="post">
        <label for="username">Username:</label><br>
        <input type="text" id="username" name="username"><br>
        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password"><br>
        <label for="file">Select a file:</label><br>
        <input type="file" id="file" name="file"><br><br>
        <input type="submit" value="Upload File">
    </form>
</body>
</html>
"""

# Display HTML form for user input
@app.get("/", response_class=HTMLResponse)
async def home():
    return html_form

# Handle file upload and upload to S3
@app.post("/upload/")
async def upload_file_to_s3(username: str = Form(...), password: str = Form(...), file: UploadFile = File(...)):
    # Validate username and password (dummy validation)
    if username != "admin" or password != "admin":
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Upload file to S3
    try:
        file_key = f'raw/{username}/{file.filename}'
        s3_client.upload_fileobj(file.file, S3_BUCKET_NAME, file_key)
        return {"message": "File uploaded successfully to S3", "filename": file_key}
    except ClientError as e:
        raise HTTPException(status_code=500, detail=f"Failed to upload file to S3: {e}")

# Run the FastAPI app with Uvicorn
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
