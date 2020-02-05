    # GraphQL Websocket Concrete5 Security Composer Package
The idea of this repo is to give all functionallity to use the [GraphQL and Websockets Composer Package](https://github.com/lemonbrain-mk/graphql_websocket) secure in Concrete5.

Use this package just as a composer Concrete5 package, cause of the composer requirings

We build a C5 Version with Siler GraphQL, Apollo V2, React and Material UI. checkout the showdown here [concrete5.lemonbrain.ch](https://concrete5.lemonbrain.ch/index.php/person#/)

This package is based on an other [package](https://github.com/lemonbrain-mk/graphql_websocket) and the documentation for it is in this [wiki](https://github.com/lemonbrain-mk/graphql_websocket/wiki)

This project is a concrete5 package that is powered entirely by [composer](https://getcomposer.org).

To install this package on a [composer based concrete5](https://github.com/concrete5/composer) site, make sure you already have `composer/installers` then run:

```sh
$ composer require lemonbrain/concrete5_graphql_websocket_security
```

Then install npm requirements

```sh
$ cd ./public/packages/concrete5_graphql_websocket_security
$ npm install
$ npx webpack --watch
```

Then install the package on Concrete5

```sh
$ ./vendor/bin/concrete5 c5:package-install concrete5_graphql_websocket_security
```