import { Sequelize } from "sequelize";

// PostgreSQL connection string
const DATABASE_URL = process.env.DATABASE_URL || "postgresql://postgres.fehluaouvxjazvteidet:Augusti@0019N@aws-1-us-east-2.pooler.supabase.com:5432/postgres";

const sequelize = new Sequelize(DATABASE_URL, {
    dialect: "postgres",
    logging: false, // Set to console.log to see SQL queries
    pool: {
        max: 5,
        min: 0,
        acquire: 30000,
        idle: 10000
    }
});

const connectDb = async () => {
    try {
        await sequelize.authenticate();
        console.log("✅ PostgreSQL Connected successfully");
        
        // Sync all models with database
        await sequelize.sync({ alter: true }); // Use { force: true } to drop tables on restart
        console.log("✅ Database synced successfully");
    } catch (error) {
        console.error("❌ Unable to connect to PostgreSQL Database:", error);
        process.exit(1);
    }
};

export { sequelize, connectDb };
export default connectDb;