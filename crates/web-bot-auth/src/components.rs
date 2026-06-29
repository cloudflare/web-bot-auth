// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

use super::ImplementationError;

/// [Signature component parameters](https://www.rfc-editor.org/rfc/rfc9421#name-http-signature-component-pa) for HTTP fields.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub enum HTTPFieldParameters {
    /// Indicates whether this HTTP header was both a structured field value and should be strictly serialized in its
    /// signature base representation.
    Sf,
    /// Indicates this HTTP header was a Dictionary structured field value and should be serialized to the `key`'s value
    /// in the signature base representation.
    Key(String),
    /// Indicates all instances of this HTTP header should be wrapped as binary structures before being combined. Typically
    /// only used when an HTTP header appears multple times and cannot be safely concatenated.
    Bs,
    /// Indicates this HTTP header appeared in the trailer, not the header section.
    Tr,
    /// Indicates this HTTP header value was obtained from the request. Typically only used in a signed response.
    Req,
}

/// A container that represents an ordered list of signature component fields. Order is significant during signing and
/// verifying.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct HTTPFieldParametersSet(pub Vec<HTTPFieldParameters>);

/// Represents an HTTP header, informally.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct HTTPField {
    /// Uniquely identified by name
    pub name: String,
    /// Parameters associated with this HTTPField. An ordered container is needed
    /// as order of serialization matters.
    pub parameters: HTTPFieldParametersSet,
}

impl TryFrom<sfv::Parameters> for HTTPFieldParametersSet {
    type Error = ImplementationError;

    fn try_from(value: sfv::Parameters) -> Result<Self, Self::Error> {
        let mut output: Vec<HTTPFieldParameters> = vec![];

        // we don't need `req_seen` or `tr_seen` because sfv merges duplicates into last one
        let (mut bs_seen, mut sf_seen, mut key_seen) = (false, false, false);

        for (key, bare_item) in &value {
            match key.as_str() {
                "sf" => {
                    if bare_item
                        .as_boolean()
                        .ok_or(ImplementationError::ParsingError(
                            "sf parameter was present on HTTP field component, but not a boolean"
                                .into(),
                        ))?
                    {
                        if bs_seen || key_seen {
                            return Err(ImplementationError::ParsingError(
                                "`bs`, `key` and `sf` parameter not simultaneously allowed".into(),
                            ));
                        }
                        output.push(HTTPFieldParameters::Sf);
                        sf_seen = true;
                    }
                }
                "bs" => {
                    if bare_item
                        .as_boolean()
                        .ok_or(ImplementationError::ParsingError(
                            "bs parameter was present on HTTP field component, but not a boolean"
                                .into(),
                        ))?
                    {
                        if sf_seen || key_seen {
                            return Err(ImplementationError::ParsingError(
                                "`bs`, `key` and `sf` parameter not simultaneously allowed".into(),
                            ));
                        }
                        output.push(HTTPFieldParameters::Bs);
                        bs_seen = true;
                    }
                }
                "tr" => {
                    if bare_item
                        .as_boolean()
                        .ok_or(ImplementationError::ParsingError(
                            "tr parameter was present on HTTP field component, but not a boolean"
                                .into(),
                        ))?
                    {
                        output.push(HTTPFieldParameters::Tr);
                    }
                }
                "req" => {
                    if bare_item
                        .as_boolean()
                        .ok_or(ImplementationError::ParsingError(
                            "req parameter was present on HTTP field component, but not a boolean"
                                .into(),
                        ))?
                    {
                        output.push(HTTPFieldParameters::Req);
                    }
                }
                "key" => {
                    if sf_seen || bs_seen {
                        return Err(ImplementationError::ParsingError(
                            "`bs`, `key` and `sf` parameter not simultaneously allowed".into(),
                        ));
                    }
                    let name = bare_item
                        .as_string()
                        .ok_or(ImplementationError::ParsingError(
                            "key parameter was present on HTTP field component, but not a string"
                                .into(),
                        ))?
                        .as_str();
                    output.push(HTTPFieldParameters::Key(name.to_string()));
                    key_seen = true;
                }
                parameter_name => {
                    return Err(ImplementationError::ParsingError(format!(
                        "Unexpected parameter `{parameter_name}` when parsing HTTP field component, only sf / bs / key / req / tr allowed"
                    )));
                }
            }
        }
        Ok(HTTPFieldParametersSet(output))
    }
}

impl TryFrom<HTTPFieldParametersSet> for sfv::Parameters {
    type Error = ImplementationError;

    fn try_from(value: HTTPFieldParametersSet) -> Result<Self, Self::Error> {
        let mut parameters = sfv::Parameters::new();

        // Test for duplicates
        let (mut req_set, mut bs_set, mut sf_set, mut key_set, mut tr_set) =
            (false, false, false, false, false);

        for param in &value.0 {
            match param {
                HTTPFieldParameters::Sf => {
                    if sf_set {
                        return Err(ImplementationError::ParsingError(
                            "`sf` parameter not allowed as duplicate".into(),
                        ));
                    }
                    if bs_set || key_set {
                        return Err(ImplementationError::ParsingError(
                            "`bs`, `key` and `sf` parameter not simultaneously allowed".into(),
                        ));
                    }
                    let key = sfv::KeyRef::constant("sf").to_owned();
                    parameters.insert(key, sfv::BareItem::Boolean(true));
                    sf_set = true;
                }
                HTTPFieldParameters::Bs => {
                    if bs_set {
                        return Err(ImplementationError::ParsingError(
                            "`bs` parameter not allowed as duplicate".into(),
                        ));
                    }
                    if sf_set || key_set {
                        return Err(ImplementationError::ParsingError(
                            "`bs`, `key` and `sf` parameter not simultaneously allowed".into(),
                        ));
                    }
                    let key = sfv::KeyRef::constant("bs").to_owned();
                    parameters.insert(key, sfv::BareItem::Boolean(true));
                    bs_set = true;
                }
                HTTPFieldParameters::Tr => {
                    if tr_set {
                        return Err(ImplementationError::ParsingError(
                            "`tr` parameter not allowed as duplicate".into(),
                        ));
                    }
                    let key = sfv::KeyRef::constant("tr").to_owned();
                    parameters.insert(key, sfv::BareItem::Boolean(true));
                    tr_set = true;
                }
                HTTPFieldParameters::Req => {
                    if req_set {
                        return Err(ImplementationError::ParsingError(
                            "`tr` parameter not allowed as duplicate".into(),
                        ));
                    }
                    let key = sfv::KeyRef::constant("req").to_owned();
                    parameters.insert(key, sfv::BareItem::Boolean(true));
                    req_set = true;
                }
                HTTPFieldParameters::Key(name) => {
                    if key_set {
                        return Err(ImplementationError::ParsingError(
                            "`key` parameter not allowed as duplicate".into(),
                        ));
                    }
                    let key = sfv::KeyRef::constant("key").to_owned();
                    let value = sfv::String::from_string(name.clone())
                        .map_err(|(e, _)| ImplementationError::ImpossibleSfvError(e))?;
                    parameters.insert(key, sfv::BareItem::String(value));
                    key_set = true;
                }
            }
        }
        Ok(parameters)
    }
}

impl TryFrom<HTTPField> for sfv::Item {
    type Error = ImplementationError;

    fn try_from(value: HTTPField) -> Result<Self, Self::Error> {
        let error_message_fragment = format!(
            "Could not coerce HTTP field name `{}` into a valid sfv Item: ",
            &value.name
        );

        Ok(sfv::Item {
            bare_item: sfv::BareItem::String(sfv::String::from_string(value.name).map_err(
                |(_, s)| {
                    ImplementationError::ParsingError(format!("{error_message_fragment}: {s}"))
                },
            )?),
            params: value.parameters.try_into()?,
        })
    }
}

/// [Signature component parameters](https://www.rfc-editor.org/rfc/rfc9421#name-http-signature-component-pa)
/// specifically for the `@query-params` derived component.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub enum QueryParamParameters {
    /// Unique identifier for the query param
    Name(String),
    /// Indicates this HTTP header value was obtained from the request. Typically only used in a signed response.
    Req,
}

/// A list of derived components, used to specify attributes of an HTTP message that otherwise can't be referenced
/// via an HTTP header but nevertheless can be used in generating a signature base. Each component here, with the sole
/// exception of `QueryParameters`, accepts a single component parameter `req.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub enum DerivedComponent {
    /// Represents `@authority` derived component
    Authority {
        /// Indicates this HTTP header value was obtained from the request. Typically only used in a signed response
        req: bool,
    },
    /// Represents `@target-uri` derived component
    TargetUri {
        /// Indicates this HTTP header value was obtained from the request. Typically only used in a signed response
        req: bool,
    },
    /// Represents `@request-target` derived component
    RequestTarget {
        /// Indicates this HTTP header value was obtained from the request. Typically only used in a signed response
        req: bool,
    },
    /// Represents `@method` derived component
    Method {
        /// Indicates this HTTP header value was obtained from the request. Typically only used in a signed response
        req: bool,
    },
    /// Represents `@path` derived component
    Path {
        /// Indicates this HTTP header value was obtained from the request. Typically only used in a signed response
        req: bool,
    },
    /// Represents `@scheme` derived component
    Scheme {
        /// Indicates this HTTP header value was obtained from the request. Typically only used in a signed response
        req: bool,
    },
    /// Represents `@query` derived component
    Query {
        /// Indicates this HTTP header value was obtained from the request. Typically only used in a signed response
        req: bool,
    },
    /// Represents the `@query-params` derived component
    QueryParams {
        /// The list of parameters associated with this field
        parameters: QueryParamParametersSet,
    },
    /// Represents `@status` derived component
    Status {
        /// Indicates this HTTP header value was obtained from the request. Typically only used in a signed response
        req: bool,
    },
}

/// A container that represents an ordered list of signature component fields. Order is significant during signing and
/// verifying.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct QueryParamParametersSet(pub Vec<QueryParamParameters>);

impl TryFrom<sfv::Parameters> for QueryParamParametersSet {
    type Error = ImplementationError;

    fn try_from(value: sfv::Parameters) -> Result<Self, Self::Error> {
        let mut output: Vec<QueryParamParameters> = vec![];

        let (mut req_seen, mut name_seen) = (false, false);

        for (key, bare_item) in &value {
            match key.as_str() {
                "req" => {
                    if bare_item
                        .as_boolean()
                        .ok_or(ImplementationError::ParsingError(
                            "`req` parameter was present on `@query-param`, but not a boolean"
                                .into(),
                        ))?
                    {
                        if req_seen {
                            return Err(ImplementationError::ParsingError(
                                "`req` parameter not allowed as duplicate".into(),
                            ));
                        }
                        output.push(QueryParamParameters::Req);
                        req_seen = true;
                    }
                }
                "name" => {
                    let name = bare_item
                        .as_string()
                        .ok_or(ImplementationError::ParsingError(
                            "`name` parameter was present on `@query-param`, but not a string"
                                .into(),
                        ))?
                        .as_str();
                    if name_seen {
                        return Err(ImplementationError::ParsingError(
                            "`name` parameter not allowed as duplicate".into(),
                        ));
                    }
                    output.push(QueryParamParameters::Name(name.to_string()));
                    name_seen = true;
                }
                parameter_name => {
                    return Err(ImplementationError::ParsingError(format!(
                        "Unexpected parameter `{parameter_name}` when parsing `@query-param, only name / req allowed"
                    )));
                }
            }
        }
        Ok(QueryParamParametersSet(output.into_iter().collect()))
    }
}

impl TryFrom<QueryParamParametersSet> for sfv::Parameters {
    type Error = ImplementationError;

    fn try_from(value: QueryParamParametersSet) -> Result<Self, Self::Error> {
        let mut sfv_parameters = sfv::Parameters::new();
        let (mut req_seen, mut name_seen) = (false, false);
        for param in &value.0 {
            match param {
                QueryParamParameters::Req => {
                    if req_seen {
                        return Err(ImplementationError::ParsingError(
                            "`req` parameter not allowed as duplicate".into(),
                        ));
                    }
                    let key = sfv::KeyRef::constant("req").to_owned();
                    sfv_parameters.insert(key, sfv::BareItem::Boolean(true));
                    req_seen = true;
                }
                QueryParamParameters::Name(name) => {
                    if name_seen {
                        return Err(ImplementationError::ParsingError(
                            "`name` parameter not allowed as duplicate".into(),
                        ));
                    }
                    let key = sfv::KeyRef::constant("name").to_owned();
                    let value = sfv::String::from_string(name.clone())
                        .map_err(|(_, s)| ImplementationError::ParsingError(format!(
                            "Could not coerce `@query-param` parameter `{}` into a valid sfv Parameter: {}",
                            &name, s
                        )))?;
                    sfv_parameters.insert(key, sfv::BareItem::String(value));
                    name_seen = true;
                }
            }
        }
        Ok(sfv_parameters)
    }
}

impl TryFrom<DerivedComponent> for sfv::Item {
    type Error = ImplementationError;

    fn try_from(value: DerivedComponent) -> Result<Self, Self::Error> {
        fn template(name: &str, req: bool) -> Result<sfv::Item, ImplementationError> {
            let mut parameters = sfv::Parameters::new();
            if req {
                let key = sfv::KeyRef::constant("req").to_owned();
                parameters.insert(key, sfv::BareItem::Boolean(true));
            }

            Ok(sfv::Item {
                bare_item: sfv::BareItem::String(
                    sfv::String::from_string(name.to_string())
                        .map_err(|(e, _)| ImplementationError::ImpossibleSfvError(e))?,
                ),
                params: parameters,
            })
        }

        match value {
            DerivedComponent::Authority { req } => template("@authority", req),
            DerivedComponent::Method { req } => template("@method", req),
            DerivedComponent::Path { req } => template("@path", req),
            DerivedComponent::TargetUri { req } => template("@target-uri", req),
            DerivedComponent::RequestTarget { req } => template("@request-target", req),
            DerivedComponent::Scheme { req } => template("@scheme", req),
            DerivedComponent::Status { req } => template("@status", req),
            DerivedComponent::Query { req } => template("@query", req),
            DerivedComponent::QueryParams { parameters } => {
                let mut sfv_parameters = sfv::Parameters::new();
                for param in &parameters.0 {
                    match param {
                        QueryParamParameters::Req => {
                            let key = sfv::KeyRef::constant("req").to_owned();
                            sfv_parameters.insert(key, sfv::BareItem::Boolean(true));
                        }
                        QueryParamParameters::Name(name) => {
                            let key = sfv::KeyRef::constant("name").to_owned();
                            let value = sfv::String::from_string(name.clone())
                                .map_err(|(e, _)| ImplementationError::ImpossibleSfvError(e))?;
                            sfv_parameters.insert(key, sfv::BareItem::String(value));
                        }
                    }
                }

                Ok(sfv::Item {
                    bare_item: sfv::BareItem::String(
                        sfv::String::from_string("@query-param".to_string())
                            .map_err(|(e, _)| ImplementationError::ImpossibleSfvError(e))?,
                    ),
                    params: parameters.try_into()?,
                })
            }
        }
    }
}

/// Represents *any* component that can be used during message signing or verifying. See documentation
/// about each wrapped variant to learn more.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub enum CoveredComponent {
    /// Represents an HTTP field that can be used as part of the `Signature-Input` field
    HTTP(HTTPField),
    /// Represents a derived component - message data not accessible as an HTTP header -
    /// that can be used as part of the `Signature-Input` field.
    Derived(DerivedComponent),
}

impl TryFrom<sfv::Item> for CoveredComponent {
    type Error = ImplementationError;

    fn try_from(value: sfv::Item) -> Result<Self, Self::Error> {
        fn fetch_req(
            params: sfv::Parameters,
            component_name: &str,
        ) -> Result<bool, ImplementationError> {
            match params.len() {
                0 => Ok(false),
                1 => {
                    for (key, val) in params {
                        if key.as_str() == "req" {
                            return val.as_boolean().ok_or(ImplementationError::ParsingError(
                                format!(
                                    "`req` parameter was present on `{component_name}`, but not a boolean"
                                ),
                            ));
                        }
                    }
                    Err(ImplementationError::ParsingError(format!(
                        "Encountered another parameter name on `{component_name}`, but only `req` allowed"
                    )))
                }
                2.. => Err(ImplementationError::ParsingError(format!(
                    "Encountered multiple parameter names on `{component_name}`, but only `req` allowed"
                ))),
            }
        }

        match value.bare_item {
            sfv::BareItem::String(inner_string) => {
                let component = match inner_string.as_str() {
                    "@authority" => CoveredComponent::Derived(DerivedComponent::Authority {
                        req: fetch_req(value.params, "@authority")?,
                    }),
                    "@method" => CoveredComponent::Derived(DerivedComponent::Method {
                        req: fetch_req(value.params, "@method")?,
                    }),
                    "@path" => CoveredComponent::Derived(DerivedComponent::Path {
                        req: fetch_req(value.params, "@path")?,
                    }),
                    "@target-uri" => CoveredComponent::Derived(DerivedComponent::TargetUri {
                        req: fetch_req(value.params, "@target-uri")?,
                    }),
                    "@scheme" => CoveredComponent::Derived(DerivedComponent::Scheme {
                        req: fetch_req(value.params, "@scheme")?,
                    }),
                    "@status" => CoveredComponent::Derived(DerivedComponent::Status {
                        req: fetch_req(value.params, "@status")?,
                    }),
                    "@query" => CoveredComponent::Derived(DerivedComponent::Query {
                        req: fetch_req(value.params, "@query")?,
                    }),
                    "@request-target" => {
                        CoveredComponent::Derived(DerivedComponent::RequestTarget {
                            req: fetch_req(value.params, "@request-target")?,
                        })
                    }
                    "@query-param" => {
                        let component = DerivedComponent::QueryParams {
                            parameters: value.params.try_into()?,
                        };

                        return Ok(CoveredComponent::Derived(component));
                    }
                    field if field.starts_with('@') => {
                        return Err(ImplementationError::ParsingError(format!(
                            "Encountered invald derived component name `{field}`, consult RFC 9421 for valid names"
                        )));
                    }
                    http => {
                        return Ok(CoveredComponent::HTTP(HTTPField {
                            name: http.to_string().to_ascii_lowercase(),
                            parameters: value.params.try_into()?,
                        }));
                    }
                };

                Ok(component)
            }
            other_type => Err(ImplementationError::ParsingError(format!(
                "Expected a stringified sfv::BareItem when parsing into a CoveredComponent, but encountered a different type {other_type:?}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use sfv::FieldType;

    use super::*;

    #[test]
    fn test_parsing_valid_derived_components() {
        for case in [
            r#""@authority""#,
            r#""@authority";req"#,
            r#""@method""#,
            r#""@method";req"#,
            r#""@path""#,
            r#""@path";req"#,
            r#""@target-uri""#,
            r#""@target-uri";req"#,
            r#""@scheme""#,
            r#""@scheme";req"#,
            r#""@status""#,
            r#""@status";req"#,
            r#""@request-target""#,
            r#""@request-target";req"#,
            r#""@query-param";name="foo""#,
            r#""@query-param";name="foo";req"#,
        ]
        .iter()
        {
            let component: CoveredComponent = sfv::Parser::new(case)
                .parse_item::<sfv::Item>()
                .unwrap()
                .try_into()
                .unwrap();
            let CoveredComponent::Derived(derived) = component else {
                panic!("Expected derived components, got HTTP")
            };
            let value: sfv::Item = derived.try_into().unwrap();
            assert_eq!(&value.serialize(), case);
        }
    }

    #[test]
    fn test_parsing_valid_http_fields() {
        for case in [
            r#""content-length""#,
            r#""content-length";sf"#,
            r#""content-length";bs"#,
            r#""content-length";tr"#,
            r#""content-length";req"#,
            r#""content-length";key="foo""#,
            r#""Content-Length";req"#,
        ]
        .iter()
        {
            let component: CoveredComponent = sfv::Parser::new(case)
                .parse_item::<sfv::Item>()
                .unwrap()
                .try_into()
                .unwrap();
            let CoveredComponent::HTTP(http) = component else {
                panic!("Expected HTTP field, got derived")
            };
            let value: sfv::Item = http.try_into().unwrap();
            assert_eq!(value.serialize(), case.to_ascii_lowercase());
        }
    }

    #[test]
    fn test_parsing_invalid_http_fields() {
        for case in [
            r#""content-length";sf;bs"#,
            r#""content-length";bs;sf"#,
            r#""content-length";req;tr;key"#,
            r#""content-length";key=1"#,
            r#""content-length";sf;req;tr;key="foo""#,
            r#""content-length";bs;req;tr;key="foo""#,
        ]
        .iter()
        {
            let item: sfv::Item = sfv::Parser::new(case).parse_item().unwrap();
            CoveredComponent::try_from(item).expect_err("This case should error");
        }
    }

    #[test]
    fn test_known_edge_cases_in_http_parsing() {
        for (case, expected) in [
            (r#""content-length";sf;sf"#, r#""content-length";sf"#),
            (r#""content-length";bs;bs"#, r#""content-length";bs"#),
            (r#""content-length";req;req"#, r#""content-length";req"#),
            (r#""content-length";tr;tr"#, r#""content-length";tr"#),
            (
                r#""content-length";key="foo";key="bar""#,
                r#""content-length";key="bar""#,
            ),
        ]
        .iter()
        {
            {
                let component: CoveredComponent = sfv::Parser::new(case)
                    .parse_item::<sfv::Item>()
                    .unwrap()
                    .try_into()
                    .unwrap();
                let CoveredComponent::HTTP(http) = component else {
                    panic!("Expected HTTP field, got derived")
                };
                let value: sfv::Item = http.try_into().unwrap();
                assert_eq!(value.serialize(), expected.to_ascii_lowercase());
            }
        }
    }

    #[test]
    fn test_known_edge_cases_in_derived_component_parsing() {
        for (case, expected) in [(
            r#""@query-param";name="foo";name="bar""#,
            r#""@query-param";name="bar""#,
        )]
        .iter()
        {
            {
                let component: CoveredComponent = sfv::Parser::new(case)
                    .parse_item::<sfv::Item>()
                    .unwrap()
                    .try_into()
                    .unwrap();
                let CoveredComponent::Derived(derived) = component else {
                    panic!("Expected derived field, got HTTP")
                };
                let value: sfv::Item = derived.try_into().unwrap();
                assert_eq!(value.serialize(), expected.to_ascii_lowercase());
            }
        }
    }

    #[test]
    fn test_parsing_invalid_derived_components() {
        for case in [
            r#""@notacomponent""#,
            r#""@authority";req=true"#,
            r#""@authority";req=1"#,
            r#""@authority";req=:fff:"#,
            r#""@authority";req="ddd""#,
            r#""@authority";invalid"#,
            r#""@method";invalid"#,
        ]
        .iter()
        {
            let item: sfv::Item = sfv::Parser::new(case).parse_item().unwrap();
            CoveredComponent::try_from(item).expect_err("This case should error");
        }
    }

    #[test]
    fn test_http_parameter_parsing_does_not_allow_duplicates_or_invalid_sets() {
        for content in [
            vec![HTTPFieldParameters::Req, HTTPFieldParameters::Req],
            vec![HTTPFieldParameters::Sf, HTTPFieldParameters::Sf],
            vec![HTTPFieldParameters::Bs, HTTPFieldParameters::Bs],
            vec![HTTPFieldParameters::Tr, HTTPFieldParameters::Tr],
            vec![
                HTTPFieldParameters::Key("foo".into()),
                HTTPFieldParameters::Key("bar".into()),
            ],
        ]
        .into_iter()
        {
            sfv::Parameters::try_from(HTTPFieldParametersSet(content))
                .expect_err("This case should error");
        }
    }

    #[test]
    fn test_query_param_parsing_does_not_allow_duplicates_or_invalid_sets() {
        for content in [
            vec![QueryParamParameters::Req, QueryParamParameters::Req],
            vec![
                QueryParamParameters::Name("foo".into()),
                QueryParamParameters::Name("bar".into()),
            ],
        ]
        .into_iter()
        {
            sfv::Parameters::try_from(QueryParamParametersSet(content))
                .expect_err("This case should error");
        }
    }
}
