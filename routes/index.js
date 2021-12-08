var bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');
var express = require('express');
var router = express.Router();
require('dotenv').config()

// cassandra-config
var ExpressCassandra = require('express-cassandra');
const { uuidFromBuffer, uuidFromString, uuid } = require('express-cassandra');
models = ExpressCassandra.createClient({
  clientOptions: {
    contactPoints: ['127.0.0.1'],
    localDataCenter: 'datacenter1',
    protocolOptions: { port: 9042 },
    keyspace: 'pklsija2021',
    queryOptions: { consistency: ExpressCassandra.consistencies.one },
    socketOptions: { readTimeout: 0 }
  },
  ormOptions: {
    defaultReplicationStrategy: {
      class: 'SimpleStrategy',
      replication_factor: 1
    },
    migration: 'safe',
  }
});


var UserModel = models.loadSchema('User', {
  fields: {
    id: "uuid",
    fullname: "text",
    email: "text",
    password: "text",
    roles: {
      type: "text",
      default: "admin"
    }
  },
  key: ["email"]
});

var NfcModel = models.loadSchema('Nfc', {
  fields: {
    id: "uuid",
    carduid: "text",
    user: "text",
    fullname: "text",
    timestamp: "timestamp",
    lng: "float",
    lat: "float",
    age: "int",
    sex: "text",
    lastdengue: "boolean",
    ns_1: "boolean",
    anosmia: "boolean"
  },
  key: ["id"]
});

var CardInfoModel = models.loadSchema('CardInfo', {
  fields: {
    id: "uuid",
    uid: "text",
    timestamp: "timestamp",
    lng: "float",
    lat: "float"
  },
  key: ["id"]
});


// Middleware authentication
const checkAuth = (...roles) => {
  return async function (req, res, next) {
    try {
      const token = req.headers.authorization.split(" ")[1]
      const decoded = jwt.verify(token, process.env.JWT_KEY)
      models.instance.User.findOne({ email: decoded.email }, function (err, result) {
        req.userData = result
        if (!roles.includes(req.userData.roles) && roles.length) {
          return res.status(403).send({
            message: 'No Access'
          })
        }
        next()
      })
    } catch (error) {
      res.status(401).send({
        message: 'Auth Failed'
      })
      return
    }
  }
}

// UserModel or models.instance.Person can now be used as the model instance
// console.log(models.instance.User === UserModel);
// console.log(models.instance.Nfc === NfcModel);

// sync the schema definition with the cassandra database table
// if the schema has not changed, the callback will fire immediately
// otherwise express-cassandra will try to migrate the schema and fire the callback afterwards
UserModel.syncDB(function (err, result) {
  if (err) {
    res.status(500).send({
      message: 'UserModel sync failed'
    })
  };
});

NfcModel.syncDB(function (err, result) {
  if (err) {
    res.status(500).send({
      message: 'NfcModel sync failed'
    })
  };
});

CardInfoModel.syncDB(function (err, result) {
  if (err) {
    res.status(500).send({
      message: 'CardInfoModel sync failed'
    })
  };
});

/* POST user regist. */
router.post('/user/register', checkAuth('superadmin'), async function (req, res, next) {
  models.instance.User.findOne({ email: req.body.email },async function (err, result) {
    if (err) throw err
    if (result) {
      res.status(403).send({
        message: 'email already taken'
      })
    }
    else {
      let pwd = await bcrypt.hash(req.body.password, 10)
      var user = new models.instance.User({
        id: ExpressCassandra.uuid(),
        fullname: req.body.fullname,
        email: req.body.email,
        password: pwd
      });
      user.save({ if_not_exist: true }, function (err, result) {
        if (err) throw err
        if (result) {
          res.status(200).send({ message: 'created' })
        }
        return
      });
    }
  })

});

// POST user login
router.post('/user/login', async (req, res) => {
  models.instance.User.findOne({ email: req.body.email }, async function (err, result) {
    if (err) throw err
    if (result) {
      var pwd = await bcrypt.compare(req.body.password, result.password)
      // console.log(req.body.password)
      if (!pwd) {
        res.status(403).send({ message: 'invalid password' })
      }
      else {
        const token = jwt.sign({
          email: result.email,
          id: result.id
        }, process.env.JWT_KEY,
          {
            // expiresIn: 24h
          })
        res.status(200).send({
          id: result.id,
          fullname: result.fullname,
          email: result.email,
          password: result.password,
          roles: result.roles,
          token: token
        })
      }
    } else {
      res.status(404).send({ message: 'user not found' })
    }
  })
})


/*GET all user*/
router.get('/user/data', checkAuth('superadmin'), (req, res, next) => {
  models.instance.User.find({}, function (err, people) {
    if (err) throw err;
    res.status(200).send(people)
  });
})

/*GET one user*/
router.get('/user/data/:userid', checkAuth(), (req, res, next) => {
  models.instance.User.findOne({ id: req.params.userid }, function (err, user) {
    if (err) throw err
    res.status(200).send(user)
  })
})

router.get('/user/profile', checkAuth(), (req, res, next) => {
  console.log(req.userData.id)
  models.instance.User.findOne({ id: req.userData.id }, { allow_filtering: true }, (err, user) => {
    if (err) throw err
    res.status(200).send(user)
  })
})


/*DELETE all user*/
router.delete('/user/delete', (req, res) => {
  models.instance.User.truncate((err) => {
    if (err) console.log(err)
    else res.status(200).send({ message: 'all data deleted' })
  })
})


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

router.post('/nfc/input', checkAuth(), async function (req, res, next) {
  console.log(req.userData.email)
  if(!req.body.lng || !req.body.lat){
    res.status(403).send({message:'lng & lat are required!'})
    return
  }
  var nfc = new models.instance.Nfc({
    id: ExpressCassandra.uuid(),
    carduid: req.body.carduid,
    user: req.userData.email,
    fullname: req.userData.fullname,
    timestamp: req.body.timestamp,
    lng: req.body.lng,
    lat: req.body.lat,
    age: req.body.age,
    sex: req.body.sex,
    lastdengue: req.body.lastdengue,
    ns_1: req.body.ns_1,
    anosmia: req.body.anosmia
  });
  nfc.save(function (err, result) {
    if (err) throw err
    if (result) {
      res.status(200).send({ message: 'nfc created' })
      return
    }
  });
});

/*GET one nfc*/
router.get('/nfc/:nfcId', checkAuth(), (req, res, next) => {
  const nfcId = req.params.nfcId
  models.instance.Nfc.findOne({id: uuidFromString(nfcId)}, (err, data) => {
    if(err) throw err
    if(req.userData.roles == 'superadmin' || req.userData.email == data.user){
      res.status(200).send(data)
      return
    }
    res.status(403).send({message:'NOOO ACCESSS'})
  })
})

/*GET all nfc (by roles)*/
router.get('/nfc/data/all', checkAuth(), (req, res, next) => {
  if(req.userData.roles == 'superadmin'){
    models.instance.Nfc.find({} ,function (err, data) {
      if (err) throw err;
      res.status(200).send(data.sort(function(x,y){
        return y.timestamp - x.timestamp
      }))
    });
  } else {
    let query = {
      user: req.userData.email
    }
    models.instance.Nfc.find(query, {allow_filtering:true}, function (err, data) {
      if (err) throw err;
      res.status(200).send(data.sort(function(x,y){
        return y.timestamp - x.timestamp
      }))
    });  
  }
})

/*DELETE one user*/
router.delete('/nfc/delete/:nfcId', checkAuth('superadmin'),(req, res) => {
  models.instance.Nfc.delete({id: uuidFromString(req.params.nfcId)}, function(err){
    if(err) console.log(err);
    else{ 
      res.status(200).send({ message: req.params.nfcId + " Deleted"})
      console.log(req.params.nfcId + " Deleted");
    }
  });
})

/*DELETE all user*/
router.delete('/nfc/delete', checkAuth('superadmin'),(req, res) => {
  models.instance.Nfc.truncate((err) => {
    if (err) console.log(err)
    else res.status(200).send({ message: 'all nfc\'s data deleted' })
  })
})

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*REGIST NEW CARD */
router.post('/card/input', checkAuth('superadmin'), async function (req, res, next) {
  var card = new models.instance.CardInfo({
    id: ExpressCassandra.uuid(),
    uid: req.body.uid,
    timestamp: req.body.timestamp,
    lng: req.body.lng,
    lat: req.body.lat
  });
  card.save(function (err, result) {
    if (err) throw err
    if (result) {
      res.status(200).send({ message: 'cardinfo registered' })
      return
    }
  });
});

/*GET all card*/
router.get('/card/data', checkAuth('superadmin'), (req, res, next) => {
  models.instance.CardInfo.find({}, function (err, data) {
    if (err) throw err;
    res.status(200).send(data.sort(function(x,y){
      return y.timestamp - x.timestamp
    }))
  });
})

module.exports = router;