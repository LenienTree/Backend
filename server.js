import bodyParser from "body-parser";
import express from "express"
import morgan from "morgan";
import cors from "cors"
import { createProxyMiddleware } from "http-proxy-middleware";
import { rateLimit } from 'express-rate-limit'

const limiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	limit: 100, // 100 requests per per 15 minutes 
	message:"Request limit exceeded"
})

const app=express();
app.use(limiter)
app.use(morgan('dev'))
app.use(cors())

app.use((req, res, next) => {
    // Skip body parsing for proxy routes
    if (req.path.startsWith('/auth') || req.path.startsWith('/events')) {
        return next();
    }
    // Apply both body parsers sequentially
    bodyParser.json()(req, res, (err) => {
        if (err) return next(err);
        bodyParser.urlencoded({extended: false})(req, res, next);
    });
});

app.get("/test",(req,res)=>{
   const content=req.body
    res.status(201).send({message:"hello from the API gateway",
        content
    })
})


app.use('/auth',createProxyMiddleware({target:'http://localhost:5001/', changeOrigin:true}));
app.use('/events',createProxyMiddleware({target:'http://localhost:5002/',changeOrigin:true}));


const PORT=5000;
app.listen(PORT,()=>{ console.log(` The app is listening on port ${PORT}`)})
