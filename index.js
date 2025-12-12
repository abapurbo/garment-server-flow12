require('dotenv').config();
const express = require('express')
const app = express()
const cors = require('cors');
const morgan = require('morgan')
const port = process.env.PORT || 4000;

app.use(morgan('dev'))
app.use(express.json())
app.use(cors())

// user verify token in firebase
const verifyFBToken = async (req, res, next) => {
    const authorization = req.headers.authorization;
    if (!authorization) {
        return res.status(401).send({ message: "Unauthorized access" });
    }

    const token = authorization.split(" ")[1];
    if (!token) {
        return res.status(401).send({ message: 'Unauthorized access' })
    }
    try {
        const decoded = await admin.auth().verifyIdToken(token);
        req.decoded_email = decoded.email
        next();
    } catch (err) {
        return res.status(401).send({ message: 'Unauthorized access' })

    }


}
const { MongoClient, ServerApiVersion } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.p9igsxk.mongodb.net/?appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    const myDB = client.db('garmentFlowDb')
    const usersCollection = myDB.collection('users');
    try {
        // Connect the client to the server	(optional starting in v4.7)
        await client.connect();

        // admin verify 
        const adminVerify = async (req, res, next) => {
            const email = req.decoded_email
            const query = { email };
            const user = await usersCollection.findOne(query);

            if (!user || user.role !== 'admin') {
                return res.status(403).send({ message: 'forbidden access' });
            }

            next();
        }
        // manager verify 
        const managerVerify = async (req, res, next) => {
            const email = req.decoded_email
            const query = { email };
            const user = await usersCollection.findOne(query);

            if (!user || user.role !== 'manager') {
                return res.status(403).send({ message: 'forbidden access' });
            }

            next();
        }

        // create user api
        app.post('/user', async (req, res) => {

            const user = req.body;
            const updateUser = {
                ...user,
                createdAt: new Date()
            }
            const result = await usersCollection.insertOne(updateUser)
            res.send(result)
        })
        // get users api
        app.get('/users', async (req, res) => {
            const resutl = await usersCollection.find().toArray();
            res.send(resutl)
        })





        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);



app.get('/', (req, res) => {
    res.send('garmentflow server site is runing....')
})

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
