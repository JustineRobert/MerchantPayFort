require 'digest'

module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class PayfortGateway < Gateway
      class_attribute :credit_card_tokenization_test_url, :credit_card_tokenization_live_url

      self.credit_card_tokenization_test_url = 'https://sbcheckout.PayFort.com/FortAPI/paymentPage'
      self.credit_card_tokenization_live_url = 'https://checkout.PayFort.com/FortAPI/paymentPage'

      self.test_url = ''
      self.live_url = ''

      self.supported_countries = ['AE']
      self.default_currency = 'AED'
      self.supported_cardtypes = [:visa, :master]

      self.homepage_url = 'http://www.payfort.com/'
      self.display_name = 'Payfort'

      STANDARD_ERROR_CODE_MAPPING = {}

      def initialize(options={})
        requires!(options, :merchant_identifier, :access_code, :sha_request_phrase, :language)
        super
      end

      def purchase(money, payment, options={})
        post = {}
        add_invoice(post, money, options)
        add_payment(post, payment)
        add_address(post, payment, options)
        add_customer_data(post, options)

        commit('sale', post)
      end

      def authorize(money, payment, options={})
        post = {}
        add_invoice(post, money, options)
        add_payment(post, payment)
        add_address(post, payment, options)
        add_customer_data(post, options)

        commit('authonly', post)
      end

      def capture(money, authorization, options={})
        commit('capture', post)
      end

      def refund(money, authorization, options={})
        commit('refund', post)
      end

      def void(authorization, options={})
        commit('void', post)
      end

      def verify(credit_card, options={})
        MultiResponse.run(:use_first_response) do |r|
          r.process { authorize(100, credit_card, options) }
          r.process(:ignore_result) { void(r.authorization, options) }
        end
      end

      def supports_scrubbing?
        true
      end

      def scrub(transcript)
        transcript
      end

      def store(credit_card, parameters={})
        post = {}

        post[:service_command] = 'TOKENIZATION'
        post[:merchant_identifier] = self.options[:merchant_identifier]
        post[:access_code] = self.options[:access_code]
        post[:merchant_reference] = self.options[:merchant_identifier]
        post[:language] = self.options[:language]
        post[:remember_me] = parameters[:remember_me] ? 'YES' : 'NO'
        # NOTE: credit card token will be sent to return url as GET parameter
        post[:return_url] = parameters[:return_url]
        post[:signature] = signature(post)

        post[:card_number] = credit_card.number
        post[:expiry_date] = "#{credit_card.year.to_s[-2,2]}#{credit_card.month}"
        post[:card_security_code] = credit_card.verification_value if credit_card.verification_value?
        post[:card_holder_name] = credit_card.name if credit_card.name

        url = test? ? self.class.credit_card_tokenization_test_url : self.class.credit_card_tokenization_live_url
        raw_ssl_request(:post, url, post_data('TOKENIZATION', post))
      end

      private

      def add_customer_data(post, options)
      end

      def add_address(post, creditcard, options)
      end

      def add_invoice(post, money, options)
        post[:amount] = amount(money)
        post[:currency] = (options[:currency] || currency(money))
      end

      def add_payment(post, payment)
      end

      def parse(body)
        {}
      end

      def commit(action, parameters)
        url = (test? ? test_url : live_url)
        response = parse(ssl_post(url, post_data(action, parameters)))

        Response.new(
          success_from(response),
          message_from(response),
          response,
          authorization: authorization_from(response),
          avs_result: AVSResult.new(code: response["some_avs_response_key"]),
          cvv_result: CVVResult.new(response["some_cvv_response_key"]),
          test: test?,
          error_code: error_code_from(response)
        )
      end

      def success_from(response)
      end

      def message_from(response)
      end

      def authorization_from(response)
      end

      def post_data(action, parameters={})
        parameters.map do |key, value|
          escaped_value = CGI.escape(value.to_s)
          "#{key}=#{escaped_value}"
        end.join('&')
      end

      def error_code_from(response)
        unless success_from(response)
          # TODO: lookup error code for this response
        end
      end

      def signature(args={})
        salt = self.options[:sha_request_phrase]
        str = args.sort.reduce(salt) {|memo, (k,v)| memo << "#{k}=#{v}"} << salt
        Digest::SHA256.hexdigest(str).upcase
      end
    end
  end
end
