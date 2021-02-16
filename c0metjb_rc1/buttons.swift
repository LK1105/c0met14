//
//  jbButton.swift
//  c0metjb_rc1
//
//  Created by Mattso on 16/02/2021.
//

import UIKit

@IBDesignable class jbButton: UIButton
{
    override func layoutSubviews() {
        super.layoutSubviews()

        updateCornerRadius()
    }

    @IBInspectable var rounded: Bool = false {
        didSet {
            updateCornerRadius()
        }
    }

    func updateCornerRadius() {
        layer.cornerRadius = rounded ? frame.size.height / 2 : 0
    }
    
}
