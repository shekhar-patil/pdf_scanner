require 'optparse'
require 'yaml'
require 'rexml/document'
require 'digest/sha2'
require 'fileutils'
require 'origami'
# require 'colorize'

module PdfScanner
  class Scanner
    DEFAULT_CONFIG_FILE = "#{File.dirname(__FILE__)}/config/pdfcop.conf.yml"
    DEFAULT_POLICY = "standard"
    SECURITY_POLICIES = {}
    ANNOTATION_RIGHTS = {
      FileAttachment: %i[allowAttachments allowFileAttachmentAnnotation],
      Sound: %i[allowSoundAnnotation],
      Movie: %i[allowMovieAnnotation],
      Screen: %i[allowScreenAnnotation],
      Widget: %i[allowAcroforms],
      RichMedia: %i[allowRichMediaAnnotation],
      :"3D" => %i[allow3DAnnotation]
    }

    def initialize(params = {})
      @options = {}
      @options[:output_log] = params[:output_log] if params[:output_log].present?
      @options[:target_file] = params[:target_file] if params[:target_file].present?
      @options[:config_file] = params[:config_file] if params[:config_file].present?
      @options[:policy] = params[:policy] if params[:policy].present?
      @options[:move_dir] = params[:dir] if params[:dir].present?
      @options[:password] = params[:passwd] if params[:passwd].present? # for encrypted file
      @errors = []
    end

    def scan
      begin
        if !@options.key?(:policy)
          @options[:policy] = DEFAULT_POLICY
        end

        if @options.key?(:move_dir) and !File.directory?(@options[:move_dir])
          abort "Error: #{@options[:move_dir]} is not a valid directory."
        end

        load_config_file(@options[:config_file] || DEFAULT_CONFIG_FILE)

        unless SECURITY_POLICIES.key?("POLICY_#{@options[:policy].upcase}")
          return "Undeclared policy `#{@options[:policy]}'"
        end

        @pdf = Origami::PDF.read(@options[:target_file],
          verbosity: Origami::Parser::VERBOSE_QUIET,
          ignore_errors: SECURITY_POLICIES["POLICY_#{@options[:policy].upcase}"]['allowParserErrors'],
          decrypt: SECURITY_POLICIES["POLICY_#{@options[:policy].upcase}"]['allowEncryption'],
          prompt_password: lambda { '' },
          password: @options[:password]
        )

        if @pdf.encrypted?
          check_rights(:allowEncryption)
        end

        catalog = @pdf.Catalog
        reject("Invalid document catalog") unless catalog.is_a?(Origami::Catalog)

        if catalog.key?(:OpenAction)
          check_rights(:allowOpenAction)
          action = catalog.OpenAction
          analyze_action(action, true, 1)
        end

        if catalog.key?(:AA)
          if catalog.AA.is_a?(Origami::Dictionary)
            aa = Origami::CatalogAdditionalActions.new(catalog.AA); aa.parent = catalog;
            analyze_action(aa.WC, false, 1) if aa.key?(:WC)
            analyze_action(aa.WS, false, 1) if aa.key?(:WS)
            analyze_action(aa.DS, false, 1) if aa.key?(:DS)
            analyze_action(aa.WP, false, 1) if aa.key?(:WP)
            analyze_action(aa.DP, false, 1) if aa.key?(:DP)
          end
        end

        if catalog.key?(:AcroForm)
          acroform = catalog.AcroForm
          if acroform.is_a?(Origami::Dictionary)
            check_rights(:allowAcroForms)
            if acroform.key?(:XFA)
              check_rights(:allowXFAForms)

              analyze_xfa_forms(acroform[:XFA].solve)
            end
          end
        end

        if @pdf.each_named_script.any?
          check_rights(:allowJS)
          check_rights(:allowJSAtOpening)
        end

        if @pdf.each_attachment.any?
          check_rights(:allowAttachments)
        end

        @pdf.each_page do |page|
          analyze_page(page, 1)
        end

        @pdf.each_object.select{|obj| obj.is_a?(Origami::Stream)}.each do |stream|
          if stream.dictionary.key?(:Filter)
            filters = stream.Filter
            filters = [ filters ] if filters.is_a?(Origami::Name)

            if filters.is_a?(Origami::Array)
              filters.each do |filter|
                case filter.value
                when :ASCIIHexDecode
                  check_rights(:allowASCIIHexFilter)
                when :ASCII85Decode
                  check_rights(:allowASCII85Filter)
                when :LZWDecode
                  check_rights(:allowLZWFilter)
                when :FlateDecode
                  check_rights(:allowFlateDecode)
                when :RunLengthDecode
                  check_rights(:allowRunLengthFilter)
                when :CCITTFaxDecode
                  check_rights(:allowCCITTFaxFilter)
                when :JBIG2Decode
                  check_rights(:allowJBIG2Filter)
                when :DCTDecode
                  check_rights(:allowDCTFilter)
                when :JPXDecode
                  check_rights(:allowJPXFilter)
                when :Crypt
                  check_rights(:allowCryptFilter)
                end
              end
            end
          end
        end
      rescue
        reject("Analysis failure")
      end

      @errors
    end

    def load_config_file(path)
      SECURITY_POLICIES.update(Hash.new(false).update YAML.load(File.read(path)))
    end

    def reject(cause)
      if @options.key?(:move_dir)
        quarantine(@options[:target_file], @options[:move_dir])
      end

      @errors << "Document rejected by policy `#{@options[:policy]}', caused by #{cause.inspect}."
    end

    def quarantine(file, quarantine_folder)
      digest = Digest::SHA256.file(file)
      ext = File.extname(file)
      dest_name = "#{File.basename(file, ext)}_#{digest}#{ext}"
      dest_path = File.join(quarantine_folder, dest_name)

      FileUtils.move(file, dest_path)
    end

    def check_rights(*required_rights)
      current_rights = SECURITY_POLICIES["POLICY_#{@options[:policy].upcase}"]

      reject(required_rights) if required_rights.any?{|right| current_rights[right.to_s] == false}
    end

    def analyze_xfa_forms(xfa)
      case xfa
      when Origami::Array then
        xml = ""
        i = 0
        xfa.each do |packet|
          if i % 2 == 1
            xml << packet.solve.data
          end

          i = i + 1
        end
      when Origami::Stream then
          xml = xfa.data
      else
          reject("Malformed XFA dictionary")
      end

      xfadoc = REXML::Document.new(xml)
      REXML::XPath.match(xfadoc, "//script").each do |script|
        case script.attributes["contentType"]
        when "application/x-formcalc" then
          check_rights(:allowFormCalc)
        else
          check_rights(:allowJS)
        end
      end
    end

    def check_annotation_rights(annot)
      subtype = annot.Subtype.value

      check_rights(*ANNOTATION_RIGHTS[subtype]) if ANNOTATION_RIGHTS.include?(subtype)
    end

    def analyze_annotation(annot, _level = 0)
      check_rights(:allowAnnotations)

      if annot.is_a?(Origami::Dictionary) and annot.key?(:Subtype)
        check_annotation_rights(annot)

        analyze_3d_annotation(annot) if annot.Subtype.value == :"3D"
      end
    end

    def analyze_3d_annotation(annot)
      # 3D annotation might pull in JavaScript for real-time driven behavior.
      return unless annot.key?(:"3DD")

      dd = annot[:"3DD"].solve
      u3dstream = nil

      case dd
      when Origami::Stream
          u3dstream = dd
      when Origami::Dictionary
          u3dstream = dd[:"3DD"].solve
      end

      if u3dstream.is_a?(Stream) and u3dstream.key?(:OnInstantiate)
        check_rights(:allowJS)

        if annot.key?(:"3DA") # is 3d view instantiated automatically?
          u3dactiv = annot[:"3DA"].solve

          check_rights(:allowJSAtOpening) if u3dactiv.is_a?(Origami::Dictionary) and (u3dactiv.A == :PO or u3dactiv.A == :PV)
        end
      end
    end

    def analyze_page(page, level = 0)
      if page.is_a?(Origami::Dictionary)
        #
        # Checking page additional actions.
        #
        if page.key?(:AA)
          if page.AA.is_a?(Origami::Dictionary)

            aa = Origami::Page::AdditionalActions.new(page.AA); aa.parent = page.AA.parent
            analyze_action(aa.O, true, level + 1) if aa.key?(:O)
            analyze_action(aa.C, false, level + 1) if aa.key?(:C)
          end
        end

        #
        # Looking for page annotations.
        #
        page.each_annotation do |annot|
          analyze_annotation(annot, level + 1)
        end
      end
    end

    def analyze_action(action, triggered_at_opening, level = 0)
      if action.is_a?(Origami::Dictionary)
        type = action[:S].is_a?(Origami::Reference) ? action[:S].solve : action[:S]

        case type.value
        when :JavaScript
          check_rights(:allowJS)
          check_rights(:allowJSAtOpening) if triggered_at_opening
        when :Launch
          check_rights(:allowLaunchAction)
        when :Named
          check_rights(:allowNamedAction)
        when :GoTo
          check_rights(:allowGoToAction)
          dest = action[:D].is_a?(Origami::Reference) ? action[:D].solve : action[:D]
          if dest.is_a?(Origami::Array) and dest.length > 0 and dest.first.is_a?(Origami::Reference)
            dest_page = dest.first.solve
            if dest_page.is_a?(Origami::Page)
              analyze_page(dest_page, level + 1)
            end
          end
        when :GoToE
          check_rights(:allowAttachments,:allowGoToEAction)
        when :GoToR
          check_rights(:allowGoToRAction)
        when :Thread
          check_rights(:allowGoToRAction) if action.key?(:F)
        when :URI
          check_rights(:allowURIAction)
        when :SubmitForm
          check_rights(:allowAcroForms,:allowSubmitFormAction)
        when :ImportData
          check_rights(:allowAcroForms,:allowImportDataAction)
        when :Rendition
          check_rights(:allowScreenAnnotation,:allowRenditionAction)
        when :Sound
          check_rights(:allowSoundAnnotation,:allowSoundAction)
        when :Movie
          check_rights(:allowMovieAnnotation,:allowMovieAction)
        when :RichMediaExecute
          check_rights(:allowRichMediaAnnotation,:allowRichMediaAction)
        when :GoTo3DView
          check_rights(:allow3DAnnotation,:allowGoTo3DAction)
        end

        if action.key?(:Next)
          check_rights(:allowChainedActions)
          analyze_action(action.Next)
        end

      elsif action.is_a?(Origami::Array)
        dest = action
        if dest.length > 0 and dest.first.is_a?(Origami::Reference)
          dest_page = dest.first.solve
          if dest_page.is_a?(Origami::Page)
            check_rights(:allowGoToAction)
            analyze_page(dest_page, level + 1)
          end
        end
      end
    end
  end
end
