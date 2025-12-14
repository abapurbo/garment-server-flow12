require('dotenv').config();
const express = require('express')
const app = express()
const cors = require('cors');
const morgan = require('morgan')
const port = process.env.PORT || 4000;

const admin = require("firebase-admin");
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf8')
const serviceAccount = JSON.parse(decoded);
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});
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
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
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
    const productCollection = myDB.collection('allProduct')
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
        // get a user role 
        app.get('/users/:email/role', verifyFBToken, async (req, res) => {
            const email = req.params.email;
            const query = { email }
            const user = await usersCollection.findOne(query);
            res.send({ role: user?.role || 'buyer' })
        })
        // user get products
        app.get('/all-product', async (req, res) => {

            // client থেকে order='asc' বা 'desc' এবং sortField='price' পাঠান
            const { limit = 0, skip = 0, sortField = 'price', order = 'desc', search = '' } = req.query;

            const filter = {};
            if (search) {
                filter.name = { $regex: search, $options: 'i' };
            }

            const sortOption = {};
            sortOption[sortField] = order === 'asc' ? 1 : -1;

            const products = await productCollection
                .find(filter)
                .sort(sortOption)
                .limit(Number(limit))
                .skip(Number(skip))
                .toArray();

            const total = await productCollection.countDocuments(filter);

            res.send({ products, total });


        });
        app.get('/home-products', async (req, res) => {
            const showOnHome = req.query.showOnHome == true

            const result = await productCollection
                .find({ showOnHome: showOnHome })
                .limit(6)
                .toArray();

            return res.send(result);

        })
        // manager all products
        app.get('/manage-products', verifyFBToken, managerVerify, async (req, res) => {
            const email = req.query.email;
            if (req.decoded_email !== email) {
                return res.status(403).send({ message: 'Forbidden access' })
            }
            const result = await productCollection.find({ providerEmail: email }).toArray()
            res.send(result)
        })
        // search products
        app.get('/search-products', verifyFBToken, async (req, res) => {
            const searchText = req.query.searchText || "";
            const query = {
                name: { $regex: searchText, $options: 'i' }
            }
            const result = await productCollection.find(query).toArray();
            res.send(result)

        })
        // add products
        app.post('/add-product', verifyFBToken, managerVerify, async (req, res) => {
            const product = req.body;
            const price = Number(product.price);
            const minOrderQty = Number(product.minOrderQty)
            const availableQty = Number(product.availableQty)
            const { displayName, ...rest } = product
            const providerEmail = req.decoded_email
            const providerName = displayName;
            const newProduct = {
                price,
                minOrderQty,
                availableQty,
                providerEmail,
                providerName,
                ...rest,
                createdAt: new Date()
            }
            console.log(newProduct)
            const result = await productCollection.insertOne(newProduct)
            res.send(result)
        })

        // create user api
        app.post('/user', async (req, res) => {
            const user = req.body;
            // Default Role
            const role = user.role || 'buyer';
            const email = user.email;
            // Check if already exists
            const existingUser = await usersCollection.findOne({ email });

            if (existingUser) {
                return res.send({ message: 'user already exists' });
            }

            // Prepare new user
            const newUser = {
                ...user,
                role,
                createdAt: new Date()
            };

            const result = await usersCollection.insertOne(newUser);
            res.send(result);
        });
        // update products
        app.patch('/update-product/:id', verifyFBToken, managerVerify, async (req, res) => {
            const email = req.query.email;
            const id = req.params.id
            const updateData = req.body;
            const query = { _id: new ObjectId(id) }
            if (req.decoded_email !== email) {
                return res.status(403).send({ message: 'Forbidden access' })
            }
            const newUpdateData = {
                $set: {
                    name: updateData.name,
                    category: updateData.category,
                    description: updateData.description,
                    price: updateData.price,
                    minOrderQty: updateData.minOrderQty,
                    availableQty: updateData.availableQty,
                    showOnHome: updateData.showOnHome,
                    image: updateData.image,
                    providerEmail: req.decoded_email,
                    paymentOption: updateData.paymentOption,
                    demoLink: updateData.demoLink,
                }
            }

            const result = await productCollection.updateOne(query, newUpdateData);
            res.send(result)

        })
        // delete products
        app.delete('/delete-product/:id', verifyFBToken, managerVerify, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await productCollection.deleteOne(query);
            res.send(result);
        })
        // get users api
        app.get('/users', verifyFBToken, adminVerify, async (req, res) => {
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
