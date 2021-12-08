var ExpressCassandra = require('express-cassandra');
var models = ExpressCassandra.createClient({
    clientOptions: {
        contactPoints: ['127.0.0.1'],
        localDataCenter: 'dc1',
        protocolOptions: { port: 9042 },
        keyspace: 'pklsija2021',
        queryOptions: {consistency: ExpressCassandra.consistencies.one}
    },
    ormOptions: {
        defaultReplicationStrategy : {
            class: 'SimpleStrategy',
            replication_factor: 1
        },
        migration: 'safe',
    }
});

var MyModel = models.loadSchema('User', {
    fields:{
        id: "uuid",
        fullname: "text",
        email: "text",
        password: "text",
        roles: "text"
    },
    key:["id"]
});

// MyModel or models.instance.Person can now be used as the model instance
console.log(models.instance.Person === MyModel);

// sync the schema definition with the cassandra database table
// if the schema has not changed, the callback will fire immediately
// otherwise express-cassandra will try to migrate the schema and fire the callback afterwards
MyModel.syncDB(function(err, result) {
    if (err) throw err;
    // result == true if any database schema was updated
    // result == false if no schema change was detected in your models
});