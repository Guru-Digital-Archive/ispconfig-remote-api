<?php
return PhpCsFixer\Config::create()
        ->setRiskyAllowed(true)
        ->setRules([
            '@PHP56Migration'                    => true,
            '@PSR2'                              => true,
            'array_syntax'                       => [
                'syntax' => 'short'
            ],
            'binary_operator_spaces'             => [
                'align_double_arrow' => true,
                'align_equals'       => true
            ],
            'single_quote'                       => true,
            'no_blank_lines_after_class_opening' => false,
        ])
        ->setFinder(PhpCsFixer\Finder::create()->in(__DIR__ . '/GDM/'));
