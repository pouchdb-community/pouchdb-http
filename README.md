pouchdb-http
======

PouchDB as an HTTP-only package.

The `pouchdb-http` preset only contains the HTTP adapter, i.e. the adapter that
allows PouchDB to talk to CouchDB using the format `new PouchDB('http://127.0.0.1:5984/mydb')`.

Use this preset if you only want to use PouchDB as an interface to CouchDB (or a Couch-compatible server).

### Usage

```bash
npm install pouchdb-http
```

```js
var PouchDB = require('pouchdb-http');
var db = new PouchDB('http://127.0.0.1:5984/mydb');
```

Note that this preset doesn't come with map/reduce (i.e. the `query()` API). If you want that, then you should do:

```js
var PouchDB = require('pouchdb-http')
  .plugin(require('pouchdb-mapreduce'));
```


For full API documentation and guides on PouchDB, see [PouchDB.com](http://pouchdb.com/). For details on PouchDB sub-packages, see the [Custom Builds documentation](http://pouchdb.com/custom.html).