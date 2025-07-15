import express from "express"
import dotenv from "dotenv"
import bodyParser from "body-parser";
import morgan from "morgan";
import cors from "cors"
import connectDb from "./db/db.js";
import eventRoutes from"./routes/eventRoutes.js"
dotenv.config();

const app=express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(morgan('common'))
app.use(cors())

connectDb();

const PORT=process.env.PORT || 5002



//routes
app.use('/',eventRoutes)

app.listen(PORT,()=>{
    console.log(`App is listening  on PORT ${PORT}`)
})