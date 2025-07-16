import { S3Client, DeleteObjectCommand } from "@aws-sdk/client-s3";
import { Upload } from "@aws-sdk/lib-storage";
import dotenv from "dotenv";

dotenv.config();

export const s3Client = new S3Client({
    region: process.env.AWS_REGION || "us-east-1",
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    },
});

// S3 bucket configuration
export const s3Config = {
    bucket: process.env.AWS_S3_BUCKET_NAME,
    region: process.env.AWS_REGION || "us-east-1",
};

// Function to generate unique file name
export const generateFileName = (originalName) => {
    const timestamp = Date.now();
    const randomString = Math.random().toString(36).substring(2, 15);
    const fileExtension = originalName.split('.').pop();
    return `events/${timestamp}-${randomString}.${fileExtension}`;
};

// Function to upload file to S3
export const uploadToS3 = async (file, fileName) => {
    try {
        console.log('Starting S3 upload...');
        console.log('Bucket:', s3Config.bucket);
        console.log('File name:', fileName);
        console.log('File size:', file.buffer.length);
        console.log('Content type:', file.mimetype);
        
        const upload = new Upload({
            client: s3Client,
            params: {
                Bucket: s3Config.bucket,
                Key: fileName,
                Body: file.buffer,
                ContentType: file.mimetype,
                // ACL: "public-read",
            },
        });
        
        const result = await upload.done();
        console.log('S3 upload successful:', result);
        
        // v3 returns Key, not Location
        const imageUrl = result.Location || `https://${s3Config.bucket}.s3.${s3Config.region}.amazonaws.com/${fileName}`;
        console.log('Generated image URL:', imageUrl);
        
        return imageUrl;
    } catch (error) {
        console.error('S3 upload error details:', {
            message: error.message,
            code: error.code,
            statusCode: error.statusCode,
            requestId: error.requestId,
            bucket: s3Config.bucket,
            fileName: fileName
        });
        throw new Error(`S3 upload failed: ${error.message}`);
    }
};

// Function to delete file from S3
export const deleteFromS3 = async (fileUrl) => {
    if (!fileUrl) return;
    
    try {
        const key = fileUrl.split('.com/')[1];
        await s3Client.send(new DeleteObjectCommand({
            Bucket: s3Config.bucket,
            Key: key,
        }));
        console.log('S3 delete successful for key:', key);
    } catch (error) {
        console.error('S3 delete error:', error.message);
        // Don't throw error as file deletion is not critical
    }
}; 