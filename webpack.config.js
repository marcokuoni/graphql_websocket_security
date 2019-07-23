const path = require('path');

module.exports = {
  mode: 'production',//'development', //production
  entry: [
    "babel-polyfill",
    './js/src'],
  output: {
    path: path.resolve(__dirname, "js/dist"),
    publicPath: 'packages/screen/js/dist/',
    filename: 'screen.js',
  },
  module: {
    rules: [
      {
        test: /\.m?js[x]$/,
        exclude: /(node_modules|bower_components)/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: [
              '@babel/preset-env',
              '@babel/preset-react'
            ],
            plugins: [
              '@babel/plugin-proposal-class-properties',
              '@babel/plugin-syntax-dynamic-import'
            ]
          }
        }
      }
    ]
  },
  stats: {
    colors: true
  },
  devtool: 'source-map',
  resolve: {
    extensions: ['.js', '.jsx'],
    alias: {
      Utilities: path.resolve(__dirname, 'js/src/utils/'),
      Log$: path.resolve(__dirname, 'js/src/utils/Log'),
    }
  }
};