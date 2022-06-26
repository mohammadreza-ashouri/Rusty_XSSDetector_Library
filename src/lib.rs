extern crate htmlstream; // anti XSS
use std::collections::HashMap;
use htmlstream::*;

/*
Author: Mo Ashouri
Contract: ashourics@gmail.com
GutHub: @mohammadreza-ashouri
Web: https://ashoury.net

This helper protect backend services against XSS attack rising from non(correctly)-sanitized inputs from different sources (network, file, db, etc.)
It's also possible to whitelist specific tags (let say your backend logic knows how to handle certain html tags)
It's mainly written to protect the code against XSS, but we may extend that to other forms of cyber attacks.

Ref (XSS): https://consensys.net/diligence/blog/2021/03/tackling-cross-site-scripting-with-smart-contracts/
           https://owasp.org/www-community/attacks/xss/


*/
pub struct XSSDetect {
    _tag: Option<Box<dyn FnMut(Position, HTMLTag) -> Option<String>>>,
    on_ignore_tag: Option<Box<dyn FnMut(Position, HTMLTag) -> Option<String>>>,
    _tag_attr: Option<Box<dyn FnMut(Position, HTMLTagAttribute) -> Option<String>>>,
    _ignore_tag_attr: Option<Box<dyn FnMut(Position, HTMLTagAttribute) -> Option<String>>>,
    permitted_tags: HashMap<String, String>,
}

impl XSSDetect {
    pub fn new() -> XSSDetect {
        XSSDetect {
            _tag: None,
            on_ignore_tag: None,
            _tag_attr: None,
            _ignore_tag_attr: None,
            permitted_tags: HashMap::new(),
        }
    }

    pub fn assign__tag<F>(&mut self, f: F) where
    F: FnMut(Position, HTMLTag) -> Option<String> + 'static {
        self._tag = Some(Box::new(f));
    }

    pub fn assign_on_ignore_tag<F>(&mut self, f: F) where
    F: FnMut(Position, HTMLTag) -> Option<String> + 'static {
        self.on_ignore_tag = Some(Box::new(f));
    }

    pub fn assign__tag_attr<F>(&mut self, f: F) where
    F: FnMut(Position, HTMLTagAttribute) -> Option<String> + 'static {
        self._tag_attr = Some(Box::new(f));
    }

    pub fn assign__ignore_tag_attr<F>(&mut self, f: F) where
    F: FnMut(Position, HTMLTagAttribute) -> Option<String> + 'static {
        self._ignore_tag_attr = Some(Box::new(f));
    }

    pub fn permit_html_tag(&mut self, name: &str, attrs: Vec<&str>) {
        for attr in attrs {
            self.permitted_tags.insert(name.to_string(), attr.to_string());
        }
    }

    pub fn load_default_white_list(&mut self) {
        self.permit_html_tag("a", vec!["href", "title"]);
    }

    fn escape(&self, html: &str) -> String {
        String::from(html).replace("<", "&lt;").replace(">", "&gt;")
    }

    pub fn sanitize_me(&self, html: &str) -> String {
        let mut ret_html = "".to_string();
        for (_, tag) in tag_iter(html) {
            println!("{:?}", tag);
            match tag.state {
                HTMLTagState::Text => ret_html.push_str(&tag.html),
                HTMLTagState::Closing | HTMLTagState::Opening | HTMLTagState::SelfClosing => {
                    match self.permitted_tags.get(&tag.name) {
                        None => ret_html.push_str(&(self.escape(&tag.html))),
                        Some(allowed_attrs) => {
                            println!("{:?}", allowed_attrs);
                            let mut attrs = "".to_string();
                            for (_, attr) in attr_iter(&tag.attributes) {
                                println!("{:?}", attr);
                                if allowed_attrs.contains(&attr.name) {
                                    println!("{:?} contains {:?}", allowed_attrs, attr.name);
                                    if attr.value.is_empty() {
                                        attrs.push_str(&attr.name);
                                    } else {
                                        attrs.push_str(&attr.name);
                                        attrs.push_str("=\"");
                                        attrs.push_str(&attr.value);
                                        attrs.push_str("\" ");
                                    }
                                }
                            }
                            match tag.state {
                                HTMLTagState::Opening => {
                                    ret_html.push_str("<");
                                    ret_html.push_str(&tag.name);
                                    ret_html.push_str(" ");
                                    ret_html.push_str(&attrs);
                                    ret_html.push_str(">");
                                },
                                HTMLTagState::Closing => {
                                    ret_html.push_str("</");
                                    ret_html.push_str(&tag.name);
                                    ret_html.push_str(">");
                                },
                                HTMLTagState::SelfClosing => {
                                    ret_html.push_str("<");
                                    ret_html.push_str(&tag.name);
                                    ret_html.push_str(" ");
                                    ret_html.push_str(&attrs);
                                    ret_html.push_str("/>");
                                },
                                _ => {}
                            }
                        },
                    }
                },
            }
        }
        return ret_html;
    }
}



#[cfg(test)]
mod unit_tests {

    use super::*;


    
#[test]
    fn test_xss_detector() {

        let mut xss = XSSDetect::new();
        xss.load_default_white_list();
        xss.permit_html_tag("a", vec!["href", "target"]);
        xss.permit_html_tag("b", vec![]);
        let html = "<a href=\"javascript:alert(/xss/)\" title=ok disabled>Hi!</a> <b>test</b>";
        let ret = xss.sanitize_me(&html);
        println!("{}\n{}", html, ret);
    }

}

