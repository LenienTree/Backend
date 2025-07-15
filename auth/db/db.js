
import mongoose from "mongoose";

const connectDb= async()=>{
    try {
        const conn= await mongoose.connect(process.env.CONNECTION_URL)
        if(!conn)
        {
            console.log("Unable to create a MongoDB connection")
        }
        else{
            console.log("Succssfully connected to mongoDB ")
        }
    } catch (error) {
        console.log("Unable to connect to the MongoDb Database", error)
    }
}

export default connectDb;