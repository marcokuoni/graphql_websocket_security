import React from "react";
import ApolloClient from 'apollo-client';
import { HttpLink } from 'apollo-link-http';
import { ApolloProvider } from "react-apollo";
import { InMemoryCache } from 'apollo-cache-inmemory';
import loadable from '@loadable/component'

import configMap from 'Utilities/GetGlobals';
// eslint-disable-next-line no-unused-vars
import log from 'Log';

function Loading() {
    return <div>Loading...</div>;
}

const LoadableSolaranlageComponent = loadable(() => import('../components/Solaranlage'), {
    fallback: Loading,
});

function Solaranlage() {
    // Create an http link:
    const httpLink = new HttpLink({
        uri: (configMap.secureProtocol ? 'https://' : 'http://') + configMap.graphqlUrl,
    });

    const client = new ApolloClient({
        link: httpLink,// link,
        cache: new InMemoryCache().restore(window.__APOLLO_STATE__),
    });

    return (
        <ApolloProvider client={client}>
            <LoadableSolaranlageComponent />
        </ApolloProvider>
    );
}

export default Solaranlage;