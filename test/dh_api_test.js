"use strict";
/**
 * @fileOverview
 * API tests for the ECDH module.
 */

/*
 * Copyright (c) 2014 Mega Limited
 * under the MIT License.
 *
 * Authors: Guy K. Kloss
 *
 * You should have received a copy of the license along with this program.
 */

var ns = require('../lib/dh');
var chai = require('chai');
var sinon = require('sinon');
var crypto = require('crypto');
var _td_dh = require('./dh_test_vectors');

var atob = function(s) { return (new Buffer(s, 'base64').toString('binary')); };
var btoa = function(s) { return (new Buffer(s, 'binary').toString('base64')); };

    var assert = chai.assert;

    var _td = _td_dh;

    // Create/restore Sinon stub/spy/mock sandboxes.
    var sandbox = null;

    beforeEach(function() {
        sandbox = sinon.sandbox.create();
    });

    afterEach(function() {
        sandbox.restore();
    });

    describe("API tests", function() {
        describe('computeKey() function', function() {
            it('compute pub key', function() {
                var result = ns.computeKey(atob(_td.ALICE_PRIV));
                assert.strictEqual(btoa(result), _td.ALICE_PUB);
            });

            it('compute secret key', function() {
                var result = ns.computeKey(atob(_td.ALICE_PRIV),
                                           atob(_td.BOB_PUB));
                assert.strictEqual(btoa(result), _td.SECRET_KEY);
            });
        });

        describe('publicKey() function', function() {
            it('compute pub key', function() {
                var result = ns.publicKey(atob(_td.ALICE_PRIV));
                assert.strictEqual(btoa(result), _td.ALICE_PUB);
            });

            it('pub key mismatch', function() {
                var origPrivKey = atob(_td.ALICE_PRIV);
                var modPrivKey = String.fromCharCode(0x42) + origPrivKey.slice(1, 32);
                var result = ns.publicKey(modPrivKey);
                assert.notStrictEqual(btoa(result), _td.ALICE_PUB);
            });
        });

        describe('generateKey() function', function() {
            var zeros = [0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0];
            var ffs = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                       0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                       0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                       0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

            var _copy = function(forced) {
                return (function (len) {
                    return (new Buffer(forced));
                });
            };

            it('generate several different private keys', function() {
                var compare = '';
                for (var i = 0; i < 5; i++) {
                    var key = ns.generateKey();
                    assert.lengthOf(key, 32);
                    assert.notStrictEqual(key, compare);
                    compare = key;
                }
            });

            it('valid keys with zeros', function() {
                sandbox.stub(crypto, 'randomBytes', _copy(zeros));
                var expected = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEA=';
                assert.strictEqual(btoa(ns.generateKey()), expected);
            });

            it('valid keys with 0xff', function() {
                sandbox.stub(crypto, 'randomBytes', _copy(ffs));
                var expected = '+P///////////////////////////////////////38=';
                assert.strictEqual(btoa(ns.generateKey()), expected);
            });
        });
    });

