import pouchCore from 'pouchdb-core';
import pouchHttp from 'pouchdb-adapter-http';

export default pouchCore.plugin(pouchHttp);
