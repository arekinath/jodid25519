"use strict";
/**
 * @fileOverview
 * Tests for internal utils functions.
 */

/*
 * Copyright (c) 2014 Mega Limited
 * under the MIT License.
 *
 * Authors: Guy K. Kloss
 *
 * You should have received a copy of the license along with this program.
 */

var ns = require('../lib/utils');

var chai = require('chai');

var _td_dh = require('./dh_test_vectors');

    var assert = chai.assert;

    var _td = _td_dh;

    describe("Tests for utils functions", function() {
        describe('format conversion test', function() {
            it('round trip comparisons hexdecode()/hexencode()', function() {
                for (var i = 0; i < 8; i++) {
                    var middle = ns.hexDecode(_td.TEST_VECTORS_HEX[i][2]);
                    assert.strictEqual(ns.hexEncode(middle),
                                       _td.TEST_VECTORS_HEX[i][2]);
                }
            });
        });
    });
