"use strict";
/**
 * @fileOverview
 * Tests for internal core functions.
 */

/*
 * Copyright (c) 2014 Mega Limited
 * under the MIT License.
 *
 * Authors: Guy K. Kloss
 *
 * You should have received a copy of the license along with this program.
 */

var ns = require('../lib/core');
var utils = require('../lib/utils');
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

    describe("Tests for core functions", function() {
        var bigv1 = utils.hexDecode('cdf248068e0d3a43176d9dcc5133b6918df6e39870c25b8646b907d38bb826c7');
        var bigv2 = utils.hexDecode('00d65862b14694fcf8706faac832a82746b3d5b8cf16c2f5bbae6e80fb15862c');
        var bigv3 = utils.hexDecode('abcde00000000000000000000000000000000000000000000000000000000000');
        describe('_bigintadd', function() {
            it('adds small numbers', function () {
                var v1 = utils.hexDecode('3');
                var v2 = utils.hexDecode('5');
                var sum = ns.bigintadd(v1, v2);
                assert.deepEqual(sum, utils.hexDecode('8'));
            });
            it('adds larger numbers', function () {
                var sum = ns.bigintadd(bigv1, bigv2);
                assert.deepEqual(sum, utils.hexDecode('cec8a0693f53cf400fde0d7719665eb8d4aab9513fd91e7c0267765486cdacf3'));
            });
        });
        describe('_addmodp', function() {
            it('adds large numbers', function () {
                var sum = ns.addmodp(bigv1, bigv3);
                assert.deepEqual(sum, utils.hexDecode('79c028068e0d3a43176d9dcc5133b6918df6e39870c25b8646b907d38bb826ed'));
            });
        });
        describe('_mulmodp', function() {
            it('multiplies trivial numbers', function () {
                var v1 = utils.hexDecode('5000');
                var v2 = utils.hexDecode('3000');
                var prod = ns.mulmodp(v1, v2);
                assert.deepEqual(prod, utils.hexDecode('f000000'));
            })
            it('multiplies small numbers', function () {
                var v1 = utils.hexDecode('3000');
                var v2 = utils.hexDecode('6123');
                var prod = ns.mulmodp(v1, v2);
                assert.deepEqual(prod, utils.hexDecode('12369000'));
            });
            it('multiplies larger numbers by smaller ones', function () {
                var v2 = utils.hexDecode('100');
                var prod = ns.mulmodp(bigv1, v2);
                assert.deepEqual(prod, utils.hexDecode('7248068e0d3a43176d9dcc5133b6918df6e39870c25b8646b907d38bb826e581'));
                v2 = utils.hexDecode('123');
                prod = ns.mulmodp(bigv1, v2);
                assert.deepEqual(prod, utils.hexDecode('1a67df7379093a43a19a5f404dc887745fa4b6482cee09a26453e577d25436f1'));
            });
            it('multiplies large numbers', function () {
                var prod = ns.mulmodp(bigv1, bigv2);
                assert.deepEqual(prod, utils.hexDecode('3d9f4067cfb18c3409c3181ed14051fecd9bc06e5cee0b06cd220ec68055cf3d'));
            });
        });
        describe('_sqrmodp', function() {
            it('squares small numbers', function () {
                var v1 = utils.hexDecode('3000');
                var sq = ns.sqrmodp(v1);
                assert.deepEqual(sq, utils.hexDecode('9000000'));
                v1 = utils.hexDecode('12340000');
                sq = ns.sqrmodp(v1);
                assert.deepEqual(sq, utils.hexDecode('14b5a9000000000'));
            });
            it('squares large numbers', function () {
                var sq = ns.sqrmodp(bigv2);
                assert.deepEqual(sq, utils.hexDecode('33da91b90c3c783c0d82be76238f138509b0f812c717b4f17358a7abfc079d45'));
            });
        });
        describe('_dbl', function() {
            it('works on small numbers', function () {
                var v1 = utils.hexDecode('30000000');
                var v2 = utils.hexDecode('10000000');
                var dbl = ns.dbl(v1, v2);
                assert.deepEqual(dbl, [
                    utils.hexDecode('400000000000000000000000000000'),
                    utils.hexDecode('10b55500000000000000000000000000000')]);
            });
            it('works on large numbers', function () {
                var dbl = ns.dbl(bigv1, bigv3);
                assert.deepEqual(dbl, [
                    utils.hexDecode('7e7396f98de65746d68e0095f4e9577ce551f745ddc8bb0a013fc81761c6da56'),
                    utils.hexDecode('5f1fa94268af87062e3b571362bf09672d22ce18fdba9bdfc5b131932c766d7a')]);
            });
        });
        describe('_generateKey()', function() {
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

            it('general test zeros', function() {
                sandbox.stub(crypto, 'randomBytes', _copy(zeros));
                var expected = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
                assert.strictEqual(btoa(ns.generateKey()), expected);
            });

            it('general test zeros, curve25519=false', function() {
                sandbox.stub(crypto, 'randomBytes', _copy(zeros));
                var expected = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
                assert.strictEqual(btoa(ns.generateKey(false)), expected);
            });

            it('general test 0xff', function() {
                sandbox.stub(crypto, 'randomBytes', _copy(ffs));
                var expected = '//////////////////////////////////////////8=';
                assert.strictEqual(btoa(ns.generateKey()), expected);
            });

            it('general test 0xff, curve25519=false', function() {
                sandbox.stub(crypto, 'randomBytes', _copy(ffs));
                var expected = '//////////////////////////////////////////8=';
                assert.strictEqual(btoa(ns.generateKey(false)), expected);
            });

            it('general test zeros, curve25519=true', function() {
                sandbox.stub(crypto, 'randomBytes', _copy(zeros));
                var expected = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEA=';
                assert.strictEqual(btoa(ns.generateKey(true)), expected);
            });

            it('general test 0xff, curve25519=true', function() {
                sandbox.stub(crypto, 'randomBytes', _copy(ffs));
                var expected = '+P///////////////////////////////////////38=';
                assert.strictEqual(btoa(ns.generateKey(true)), expected);
            });
        });
    });

