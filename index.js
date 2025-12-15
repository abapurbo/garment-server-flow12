require('dotenv').config();
const express = require('express')
const app = express()
const cors = require('cors');
const morgan = require('morgan')
const port = process.env.PORT || 4000;
const stripe = require('stripe')(process.env.Secret_key);
const admin = require("firebase-admin");
const crypto = require('crypto')


const decoded = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf8')
const serviceAccount = JSON.parse(decoded);
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});


// order id genarete 
function generateOrderId() {
    const prefix = "ORD"; // Order prefix
    const date = new Date()
        .toISOString()
        .slice(0, 10)
        .replace(/-/g, ""); // YYYYMMDD

    const random = crypto
        .randomBytes(3)
        .toString("hex")
        .toUpperCase(); // 6-char random

    return `${prefix}-${date}-${random}`;
}

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
    const orderCollection = myDB.collection('buyerOrder')
    // order payment method validation
    const validateOrder = (product, paymentMethod, orderQty) => {
        if (!product) {
            throw new Error("Product not found");
        }

        if (!product.paymentOptions.includes(paymentMethod)) {
            throw new Error("This payment method is not allowed for this product");
        }

        if (product.availableQty < orderQty) {
            throw new Error("Insufficient stock");
        }
    };


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

        //payment stripe order
        app.post("/payment-checkout-session", verifyFBToken, async (req, res) => {
            try {
                const { productId, quantity } = req.body;
                const qty = Number(quantity);

                // Product fetch from DB
                const product = await productCollection.findOne({
                    _id: new ObjectId(productId),
                });

                if (!product) {
                    return res.status(404).send({ message: "Product not found" });
                }

                //  Payment method validation
                if (!product.paymentOption?.includes("Stripe")) {
                    return res
                        .status(400)
                        .send({ message: "Stripe payment not allowed for this product" });
                }

                //  Stock validation
                if (qty > product.availableQty) {
                    return res.status(400).send({ message: "Insufficient stock" });
                }

                //  Amount from DB (NOT client)
                const amount = product.price * qty * 100;

                const session = await stripe.checkout.sessions.create({
                    line_items: [
                        {
                            price_data: {
                                currency: "usd",
                                unit_amount: amount,
                                product_data: {
                                    name: product.name,
                                },
                            },
                            quantity: qty,
                        },
                    ],
                    mode: "payment",
                    metadata: {
                        productId: product._id.toString(),
                    },
                    customer_email: req.decoded_email,
                    success_url: `${process.env.SITE_DOMAIN}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
                    cancel_url: `${process.env.SITE_DOMAIN}/orderForm/${productId}`,
                });

                res.send({ url: session.url });
            } catch (err) {
                console.error(err);
                res.status(500).send({ message: "Stripe session error" });
            }
        }
        );



        // payment success
        app.patch('/payment-success', async (req, res) => {
            const sessionId = req.query.session_id;
            const session = await stripe.checkout.sessions.retrieve(sessionId);

            // console.log('session retrieve', session)
            const transactionId = session.payment_intent;
            const query = { transactionId: transactionId }

            // checking already payment in database
            // const paymentExist = await paymentCollection.findOne(query);
            // // console.log(paymentExist);
            // if (paymentExist) {
            //     return res.send({
            //         message: 'already exists',
            //         transactionId,
            //         trackingId: paymentExist.trackingId
            //     })
            // }

            // use the previous tracking id created during the parcel create which was set to the session metadata during session creation
            const orderId = session.metadata.orderId;

            if (session.payment_status === 'paid') {
                const id = session.metadata.productId;
                const query = { _id: new ObjectId(id) }
                const update = {
                    $set: {
                        paymentStatus: 'paid',
                    }
                }

                const result = await Collection.updateOne(query, update);

                const payment = {
                    amount: session.amount_total / 100,
                    currency: session.currency,
                    byerEmail: session.customer_email,
                    orderId: session.metadata.productId,
                    productName: session.metadata.productName,
                    transactionId: session.payment_intent,
                    paymentStatus: session.payment_status,
                    paidAt: new Date(),
                    orderId: orderId
                }


                const resultPayment = await orderCollection.insertOne(payment);

                logTracking(trackingId, 'parcel_paid')

                return res.send({
                    success: true,
                    modifyOrder: result,
                    orderId: orderId,
                    transactionId: session.payment_intent,
                    paymentInfo: resultPayment
                })
            }
            return res.send({ success: false })
        })




        // product cod order
        app.post("/orders", verifyFBToken, async (req, res) => {
            try {
                const {
                    productId,
                    quantity,
                    contactNumber,
                    deliveryAddress,
                    notes,
                    paymentMethod,
                } = req.body;

                const qty = Number(quantity);

                const product = await productCollection.findOne({
                    _id: new ObjectId(productId),
                });

                if (!product) {
                    return res.status(404).send({ message: "Product not found" });
                }

                // 🔐 payment method validation
                if (!product.paymentOption?.includes(paymentMethod)) {
                    return res.status(400).send({
                        message: `Payment method ${paymentMethod} not allowed for this product`,
                    });
                }

                // stock check
                if (qty > product.availableQty) {
                    return res.status(400).send({ message: "Insufficient stock" });
                }

                const order = {
                    orderId: generateOrderId(),
                    productId: product._id,
                    productName: product.name,
                    buyerEmail: req.decoded_email,
                    quantity: qty,
                    orderPrice: qty * product.price,
                    paymentMethod,
                    paymentStatus:
                        paymentMethod === "Stripe" ? "Pending" : "Unpaid",
                    status: "Pending",
                    createdAt: new Date(),
                    contactNumber,
                    deliveryAddress,
                    notes,
                };

                // atomic stock reduce
                await productCollection.updateOne(
                    { _id: product._id, availableQty: { $gte: qty } },
                    { $inc: { availableQty: -qty } }
                );

                await orderCollection.insertOne(order);

                res.send({
                    success: true,
                    message:
                        paymentMethod === "Stripe"
                            ? "Order placed, proceed to payment"
                            : "Order placed successfully (Cash on Delivery)",
                    orderId: order.orderId,
                });
            } catch (err) {
                console.error(err);
                res.status(500).send({ message: "Server error" });
            }
        });





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
        // product details
        app.get('/product-details/:id', verifyFBToken, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await productCollection.findOne(query);
            res.send(result)
        })

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
