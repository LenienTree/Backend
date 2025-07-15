import { s3Client, s3Config } from './utils/s3Config.js';
import { HeadBucketCommand } from '@aws-sdk/client-s3';

async function testS3Connection() {
    try {
        console.log('🔍 Testing S3 v3 connection...');
        console.log('Bucket:', s3Config.bucket);
        console.log('Region:', s3Config.region);
        console.log('Access Key ID:', process.env.AWS_ACCESS_KEY_ID ? '✅ Set' : '❌ Missing');
        console.log('Secret Access Key:', process.env.AWS_SECRET_ACCESS_KEY ? '✅ Set' : '❌ Missing');
        
        // Test bucket access
        const command = new HeadBucketCommand({ Bucket: s3Config.bucket });
        await s3Client.send(command);
        
        console.log('✅ S3 v3 connection successful!');
        console.log('✅ Bucket exists and is accessible.');
        
        return true;
    } catch (error) {
        console.error('❌ S3 v3 connection failed:', error.message);
        console.error('Error code:', error.Code || error.code);
        console.error('Error status:', error.$metadata?.httpStatusCode);
        
        if (error.name === 'NoSuchBucket') {
            console.log('\n💡 The bucket does not exist. Please create it first.');
        } else if (error.name === 'AccessDenied') {
            console.log('\n💡 Access denied. Check your AWS credentials and permissions.');
        } else if (error.name === 'InvalidAccessKeyId') {
            console.log('\n💡 Invalid access key. Check your AWS_ACCESS_KEY_ID.');
        } else if (error.name === 'SignatureDoesNotMatch') {
            console.log('\n💡 Invalid secret key. Check your AWS_SECRET_ACCESS_KEY.');
        }
        
        return false;
    }
}

// Run the test
console.log('🚀 Testing AWS SDK v3 S3 Configuration...\n');
testS3Connection()
    .then(success => {
        if (success) {
            console.log('\n🎉 S3 v3 is properly configured!');
            console.log('You can now use the API endpoints for file uploads.');
        } else {
            console.log('\n❌ Please fix the S3 configuration before proceeding.');
            process.exit(1);
        }
    })
    .catch(console.error); 