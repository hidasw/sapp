<pre>
<?php
/*
    This file is part of SAPP

    Simple and Agnostic PDF Parser (SAPP) - Parse PDF documents in PHP (and update them)
    Copyright (C) 2020 - Carlos de Alfonso (caralla76@gmail.com)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

use ddn\sapp\PDFDoc;

require_once('../vendor/autoload.php');

        //$doc = PDFDoc::from_string(file_get_contents('sapp_ecc_pades_b-lta.pdf'));
        $doc = PDFDoc::from_string(file_get_contents('sapp_ecc_pades_b-b.pdf'));

        $toid = null;

        if ($doc === false)
            fwrite(STDERR, "failed to parse file " . $argv[1]);
        else {
            //print_r($doc);
            $b = $doc->to_pdf_file_b();
            print_r($doc);
            //print_r($b->get_raw());
            //print_r($doc->to_pdf_file_s());
            //foreach ($doc->get_object_iterator() as $oid => $object) {
            //    if ($toid !== null) {
            //        if ($oid != $toid) {
            //            continue;
            //        }
            //    }

            //    if ($object === false)
            //        continue;
            //    if ($object["Filter"] == "/FlateDecode") {
            //        if ($object["Subtype"] != "/Image") {
            //            $stream = $object->get_stream(false);
            //            if ($stream !== false) {
            //                unset($object["Filter"]);
            //                $object->set_stream($stream, false);
            //                $doc->add_object($object);
            //            }
            //        }
            //    }
                // Not needed because we are rebuilding the document
            //    if ($object["Type"] == "/ObjStm") {
            //        $object->set_stream("", false);
            //        $doc->add_object($object);
            //    }
                // Do not want images to be uncompressed
            //    if ($object["Subtype"] == "/Image") {
            //        $object->set_stream("");
            //        $doc->add_object($object);
            //    }
            //    if ($toid != null) {
            //        print($object->get_stream(false));
            //    }
            //}
            //if ($toid === null)
            //    echo $doc->to_pdf_file_s(true);
        //}
    }

