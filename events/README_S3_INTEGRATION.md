 # S3 Integration for Event Image Uploads

This document explains how to set up and use the S3 integration for handling event image uploads in the LenienTree backend.

## Features

- ✅ Image upload to AWS S3 bucket
- ✅ Automatic file validation (images only)
- ✅ File size limits (5MB max)
- ✅ Unique file naming to prevent conflicts
- ✅ Automatic cleanup of old images when updating
- ✅ Error handling for upload failures
- ✅ Support for creating events with images
- ✅ Support for updating event images
- ✅ Separate endpoint for image-only uploads

## Setup Instructions

### 1. AWS S3 Configuration

1. Create an AWS S3 bucket for storing event images
2. Configure CORS on your S3 bucket:

```json
[
    {
        "AllowedHeaders": ["*"],
        "AllowedMethods": ["GET", "POST", "PUT", "DELETE"],
        "AllowedOrigins": ["*"],
        "ExposeHeaders": []
    }
]
```

3. Set bucket permissions to allow public read access for images

### 2. Environment Variables

Create a `.env` file in the `events` directory with the following variables:

```env
# Database Configuration
MONGODB_URI=your_mongodb_connection_string

# AWS S3 Configuration
AWS_ACCESS_KEY_ID=your_aws_access_key_id
AWS_SECRET_ACCESS_KEY=your_aws_secret_access_key
AWS_REGION=us-east-1
AWS_S3_BUCKET_NAME=your_s3_bucket_name

# Server Configuration
PORT=5002
```

### 3. Install Dependencies

The following packages have been added to `package.json`:

```bash
npm install multer aws-sdk multer-s3
```

## API Endpoints

### 1. Create Event with Image

**POST** `/events/create`

Upload an event with an optional image file.

**Form Data:**
- `eventname` (required): Name of the event
- `college` (required): College name
- `location` (required): Event location
- `type` (optional): Event type (default: "hackathon")
- `community` (optional): Community name
- `sponsors` (optional): Array of sponsor names
- `createdBy` (optional): Creator's name
- `role` (optional): Creator's role
- `eventimage` (optional): Image file (max 5MB, images only)

**Example Response:**
```json
{
  "_id": "64f8a1b2c3d4e5f6a7b8c9d0",
  "eventname": "Tech Hackathon 2024",
  "eventimage": "https://your-bucket.s3.amazonaws.com/events/1734567890123-abc123.jpg",
  "college": "MIT",
  "location": "Cambridge, MA",
  "type": "hackathon",
  "status": "pending",
  "createdAt": "2024-01-15T10:30:00.000Z",
  "updatedAt": "2024-01-15T10:30:00.000Z"
}
```

### 2. Update Event with Image

**PUT** `/events/update/:id`

Update an existing event with optional image replacement.

**Form Data:**
- All event fields (same as create)
- `eventimage` (optional): New image file (replaces existing image)

**Features:**
- Automatically deletes old image from S3 when new image is uploaded
- Preserves existing image if no new image is provided

### 3. Upload Image for Existing Event

**POST** `/events/upload-image/:id`

Upload/replace image for an existing event.

**Form Data:**
- `eventimage` (required): Image file (max 5MB, images only)

**Example Response:**
```json
{
  "message": "Image uploaded successfully",
  "eventimage": "https://your-bucket.s3.amazonaws.com/events/1734567890123-abc123.jpg",
  "event": {
    "_id": "64f8a1b2c3d4e5f6a7b8c9d0",
    "eventname": "Tech Hackathon 2024",
    "eventimage": "https://your-bucket.s3.amazonaws.com/events/1734567890123-abc123.jpg",
    // ... other event fields
  }
}
```

### 4. Get All Events

**GET** `/events/getAll`

Returns all events with their image URLs.

### 5. Get Event by ID

**GET** `/events/get/:id`

Returns a specific event by ID.

### 6. Delete Event

**DELETE** `/events/delete/:id`

Deletes an event and automatically removes its associated image from S3.

## File Validation

The system automatically validates uploaded files:

- **File Type**: Only image files are allowed (JPEG, PNG, GIF, etc.)
- **File Size**: Maximum 5MB per file
- **File Count**: Only one file per request

## Error Handling

The system provides detailed error messages for:

- Invalid file types
- File size exceeded
- Missing required fields
- S3 upload failures
- Database errors

## File Storage Structure

Images are stored in S3 with the following structure:
```
your-bucket/
└── events/
    ├── 1734567890123-abc123.jpg
    ├── 1734567890124-def456.png
    └── ...
```

## Security Considerations

1. **File Validation**: Only image files are accepted
2. **Size Limits**: 5MB maximum file size
3. **Unique Naming**: Prevents file name conflicts
4. **Access Control**: Images are stored with public read access
5. **Cleanup**: Old images are automatically deleted when replaced

## Testing

You can test the endpoints using tools like Postman or curl:

```bash
# Create event with image
curl -X POST http://localhost:5002/events/create \
  -F "eventname=Test Event" \
  -F "college=Test College" \
  -F "location=Test Location" \
  -F "eventimage=@/path/to/your/image.jpg"

# Upload image for existing event
curl -X POST http://localhost:5002/events/upload-image/64f8a1b2c3d4e5f6a7b8c9d0 \
  -F "eventimage=@/path/to/your/new-image.jpg"
```

## Troubleshooting

### Common Issues

1. **AWS Credentials Error**: Ensure your AWS credentials are correctly set in the `.env` file
2. **Bucket Not Found**: Verify the bucket name and region in your `.env` file
3. **Permission Denied**: Check that your AWS user has S3 upload permissions
4. **CORS Errors**: Ensure your S3 bucket has proper CORS configuration

### Debug Mode

Enable debug logging by adding to your `.env` file:
```env
DEBUG=true
```

This will provide detailed logs for S3 operations and file uploads.